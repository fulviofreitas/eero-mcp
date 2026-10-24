//! Settings read from an injectable environment map.
//!
//! Only this module reads the environment, and only through [`EnvMap`]: `main` builds one from
//! the process environment ([`EnvMap::from_process`]), tests build one from literal pairs
//! ([`EnvMap::from_pairs`]). `unsafe` is forbidden, so tests never mutate the process
//! environment (`std::env::set_var` is `unsafe` in edition 2024).
//!
//! rusteero's own environment-reading session constructor is deliberately not used: it reads the
//! real process environment, and its value-level validator is not public. [`token_shape_ok`]
//! applies the same rule here.
//!
//! # eero-mcp's own credential store
//!
//! From 0.2.0 the login subcommand and the login tool keep the session in eero-mcp's own store:
//! the OS keyring entry [`OWN_KEYRING_SERVICE`] / [`OWN_KEYRING_ACCOUNT`] (keyring builds, unless
//! `EERO_MCP_NO_KEYRING` is 1) with the own file [`OWN_FILE_NAME`] in the own directory as the
//! fallback. The own directory is, in order: `EERO_MCP_CONFIG_DIR` (absolute); on Windows
//! `%APPDATA%\eero-mcp`; `$XDG_CONFIG_HOME/eero-mcp` (absolute values only, per the XDG base
//! directory rule); `$HOME/.config/eero-mcp`; otherwise there is no own file.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::PathBuf;

use secrecy::SecretString;
use url::{Host, Url};

/// Session token, the first credential source.
pub const TOKEN_VAR: &str = "RUSTEERO_SESSION_TOKEN";
/// Explicit path of a credential-record file.
pub const SESSION_FILE_VAR: &str = "EERO_MCP_SESSION_FILE";
/// eeroctl's configuration directory.
pub const EEROCTL_CONFIG_DIR_VAR: &str = "EEROCTL_CONFIG_DIR";
/// Windows application-data directory (eeroctl's default location on Windows).
pub const APPDATA_VAR: &str = "APPDATA";
/// Home directory (eeroctl's default location elsewhere).
pub const HOME_VAR: &str = "HOME";
/// Development and testing only: API base override.
pub const API_BASE_URL_VAR: &str = "EERO_MCP_API_BASE_URL";
/// eero-mcp's own configuration directory (absolute), holding its session file.
pub const CONFIG_DIR_VAR: &str = "EERO_MCP_CONFIG_DIR";
/// Base of the own configuration directory on systems other than Windows (absolute values only).
pub const XDG_CONFIG_HOME_VAR: &str = "XDG_CONFIG_HOME";
/// Set to `1` to skip both keyring entries (no read, no write) in keyring builds.
pub const NO_KEYRING_VAR: &str = "EERO_MCP_NO_KEYRING";

/// Every variable this crate reads. [`EnvMap::from_process`] copies only these.
pub const VARS: [&str; 9] = [
    TOKEN_VAR,
    SESSION_FILE_VAR,
    EEROCTL_CONFIG_DIR_VAR,
    APPDATA_VAR,
    HOME_VAR,
    API_BASE_URL_VAR,
    CONFIG_DIR_VAR,
    XDG_CONFIG_HOME_VAR,
    NO_KEYRING_VAR,
];

/// The keyring service of eero-mcp's own entry. Never the shared `eero-api` service.
pub const OWN_KEYRING_SERVICE: &str = "eero-mcp";
/// The keyring account of eero-mcp's own entry.
pub const OWN_KEYRING_ACCOUNT: &str = "auth-tokens";
/// The file name of eero-mcp's own session record, inside the own directory.
pub const OWN_FILE_NAME: &str = "session.json";
/// The folder name of the own directory under a configuration base.
const OWN_DIR_NAME: &str = "eero-mcp";

/// The file name eeroctl keeps its credential record in.
const COOKIES_FILE: &str = "cookies.json";

/// A snapshot of the environment variables this crate reads. It can hold the raw session token, so
/// `Debug` lists the variable names only, never the values.
#[derive(Clone, Default)]
pub struct EnvMap(HashMap<OsString, OsString>);

impl fmt::Debug for EnvMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut names: Vec<&OsString> = self.0.keys().collect();
        names.sort();
        f.debug_struct("EnvMap")
            .field("variables", &names)
            .finish_non_exhaustive()
    }
}

impl EnvMap {
    /// An empty environment.
    pub fn new() -> Self {
        Self::default()
    }

    /// Captures the variables in [`VARS`] from the process environment. Unrelated variables are
    /// not copied.
    pub fn from_process() -> Self {
        let mut map = HashMap::new();
        for name in VARS {
            if let Some(value) = std::env::var_os(name) {
                map.insert(OsString::from(name), value);
            }
        }
        Self(map)
    }

    /// Builds an environment from literal pairs (tests).
    pub fn from_pairs<K, V>(pairs: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<OsString>,
        V: Into<OsString>,
    {
        Self(
            pairs
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        )
    }

    /// The raw value of `name`, if set.
    pub fn get(&self, name: &str) -> Option<&OsStr> {
        self.0.get(OsStr::new(name)).map(OsString::as_os_str)
    }

    /// The value of `name` unless it is unset or empty (for directory variables, where an empty
    /// value means "not configured").
    fn non_empty(&self, name: &str) -> Option<&OsStr> {
        self.get(name).filter(|value| !value.is_empty())
    }
}

/// A rejected configuration. The messages carry no secret and no configured value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigError {
    /// `RUSTEERO_SESSION_TOKEN` is set but empty, not valid UTF-8 or not printable ASCII.
    InvalidSessionToken,
    /// `EERO_MCP_SESSION_FILE` is set but empty.
    EmptySessionFile,
    /// `EERO_MCP_API_BASE_URL` is not an https URL or an http URL on a loopback host.
    InvalidApiBaseUrl,
    /// `EERO_MCP_CONFIG_DIR` is set but empty or not an absolute path.
    InvalidConfigDir,
    /// `EERO_MCP_NO_KEYRING` is set to anything other than `1`.
    InvalidNoKeyring,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidSessionToken => {
                "RUSTEERO_SESSION_TOKEN is set but invalid: it must be non-empty printable ASCII \
                 with no CR or LF, and it is never trimmed"
            }
            Self::EmptySessionFile => "EERO_MCP_SESSION_FILE is set but empty",
            Self::InvalidApiBaseUrl => {
                "EERO_MCP_API_BASE_URL is rejected: it must be an https URL, or an http URL on \
                 localhost, 127.0.0.1 or [::1], with no credentials, query or fragment"
            }
            Self::InvalidConfigDir => {
                "EERO_MCP_CONFIG_DIR is set but invalid: it must be a non-empty absolute path"
            }
            Self::InvalidNoKeyring => "EERO_MCP_NO_KEYRING is set but invalid: the only value is 1",
        })
    }
}

impl std::error::Error for ConfigError {}

/// Everything configured through the environment.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The validated `RUSTEERO_SESSION_TOKEN`, when set.
    pub session_token: Option<SecretString>,
    /// `EERO_MCP_SESSION_FILE`, when set: unreadable or unparsable fails startup.
    pub session_file: Option<PathBuf>,
    /// eeroctl's default `cookies.json`, consulted only when `session_file` is unset.
    pub default_session_file: Option<PathBuf>,
    /// `EERO_MCP_API_BASE_URL`, when set and accepted (development and testing only).
    pub api_base_url: Option<String>,
    /// eero-mcp's own session file ([`OWN_FILE_NAME`] in the own directory), when a directory can
    /// be determined. Read by the credential chain; written only by login and logout.
    pub own_file: Option<PathBuf>,
    /// Whether the OS keyring may be used (`EERO_MCP_NO_KEYRING` is not 1). Meaningful in builds
    /// with the `keyring` feature only; headless builds never touch a keyring.
    pub keyring_enabled: bool,
}

impl Settings {
    /// Reads the settings from `env`.
    pub fn from_env(env: &EnvMap) -> Result<Self, ConfigError> {
        Self::from_env_for(env, cfg!(windows))
    }

    /// As [`Settings::from_env`], with the platform made explicit so both discovery rules are
    /// testable on any host.
    pub fn from_env_for(env: &EnvMap, windows: bool) -> Result<Self, ConfigError> {
        let session_token = match env.get(TOKEN_VAR) {
            None => None,
            Some(value) => {
                let text = value.to_str().ok_or(ConfigError::InvalidSessionToken)?;
                if !token_shape_ok(text) {
                    return Err(ConfigError::InvalidSessionToken);
                }
                Some(SecretString::from(text.to_owned()))
            }
        };

        let session_file = match env.get(SESSION_FILE_VAR) {
            None => None,
            Some(value) if value.is_empty() => return Err(ConfigError::EmptySessionFile),
            Some(value) => Some(PathBuf::from(value)),
        };

        let api_base_url = match env.get(API_BASE_URL_VAR) {
            None => None,
            Some(value) => {
                let text = value.to_str().ok_or(ConfigError::InvalidApiBaseUrl)?;
                if !api_base_url_allowed(text) {
                    return Err(ConfigError::InvalidApiBaseUrl);
                }
                Some(text.to_owned())
            }
        };

        let keyring_enabled = match env.get(NO_KEYRING_VAR) {
            None => true,
            Some(value) if value == "1" => false,
            Some(_) => return Err(ConfigError::InvalidNoKeyring),
        };

        Ok(Self {
            session_token,
            session_file,
            default_session_file: default_session_file(env, windows),
            api_base_url,
            own_file: own_dir(env, windows)?.map(|dir| dir.join(OWN_FILE_NAME)),
            keyring_enabled,
        })
    }
}

/// rusteero's token-shape rule: non-empty, every byte in `0x20..=0x7E` (so no CR or LF), never
/// trimmed.
pub fn token_shape_ok(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|byte| (0x20..=0x7E).contains(&byte))
}

/// eeroctl's default credential file: `cookies.json` in `EEROCTL_CONFIG_DIR`; else, on Windows,
/// in `APPDATA\eeroctl`; else in `.config/eeroctl` under `HOME`. Empty variables count as unset.
fn default_session_file(env: &EnvMap, windows: bool) -> Option<PathBuf> {
    if let Some(dir) = env.non_empty(EEROCTL_CONFIG_DIR_VAR) {
        return Some(PathBuf::from(dir).join(COOKIES_FILE));
    }
    if windows && let Some(appdata) = env.non_empty(APPDATA_VAR) {
        return Some(PathBuf::from(appdata).join("eeroctl").join(COOKIES_FILE));
    }
    let home = env.non_empty(HOME_VAR)?;
    Some(
        PathBuf::from(home)
            .join(".config")
            .join("eeroctl")
            .join(COOKIES_FILE),
    )
}

/// eero-mcp's own configuration directory: `EERO_MCP_CONFIG_DIR` (absolute; set but empty or
/// relative is an error); else, on Windows, `eero-mcp` under `APPDATA`; else `eero-mcp` under an
/// absolute `XDG_CONFIG_HOME`; else `.config/eero-mcp` under `HOME`; else none. Empty `APPDATA`,
/// `XDG_CONFIG_HOME` and `HOME` count as unset, and a relative `XDG_CONFIG_HOME` is ignored.
fn own_dir(env: &EnvMap, windows: bool) -> Result<Option<PathBuf>, ConfigError> {
    if let Some(dir) = env.get(CONFIG_DIR_VAR) {
        let dir = PathBuf::from(dir);
        if dir.as_os_str().is_empty() || !dir.is_absolute() {
            return Err(ConfigError::InvalidConfigDir);
        }
        return Ok(Some(dir));
    }
    if windows && let Some(appdata) = env.non_empty(APPDATA_VAR) {
        return Ok(Some(PathBuf::from(appdata).join(OWN_DIR_NAME)));
    }
    if let Some(base) = env.non_empty(XDG_CONFIG_HOME_VAR) {
        let base = PathBuf::from(base);
        if base.is_absolute() {
            return Ok(Some(base.join(OWN_DIR_NAME)));
        }
    }
    Ok(env
        .non_empty(HOME_VAR)
        .map(|home| PathBuf::from(home).join(".config").join(OWN_DIR_NAME)))
}

/// The `EERO_MCP_API_BASE_URL` rule: https, or http on a loopback host (`localhost`,
/// `127.0.0.1`, `[::1]`). The token is sent to whatever origin is configured, so anything else
/// is refused, as are credentials, a query or a fragment in the URL.
pub fn api_base_url_allowed(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() {
        return false;
    }
    if url.query().is_some() || url.fragment().is_some() {
        return false;
    }
    match (url.scheme(), url.host()) {
        ("https", Some(_)) => true,
        ("http", Some(Host::Domain(domain))) => domain == "localhost",
        ("http", Some(Host::Ipv4(address))) => address.octets() == [127, 0, 0, 1],
        ("http", Some(Host::Ipv6(address))) => address.is_loopback() && address.segments()[7] == 1,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use secrecy::ExposeSecret;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvMap {
        EnvMap::from_pairs(pairs.iter().copied())
    }

    fn settings(pairs: &[(&str, &str)]) -> Result<Settings, ConfigError> {
        Settings::from_env_for(&env(pairs), false)
    }

    #[test]
    fn an_empty_environment_configures_nothing() {
        let settings = settings(&[]).expect("valid");
        assert!(settings.session_token.is_none());
        assert!(settings.session_file.is_none());
        assert!(settings.default_session_file.is_none());
        assert!(settings.api_base_url.is_none());
    }

    #[test]
    fn the_environment_snapshot_never_prints_a_value() {
        let env = EnvMap::from_pairs([(TOKEN_VAR, "super-secret-token"), (HOME_VAR, "/home/user")]);
        let rendered = format!("{env:?}");
        assert!(!rendered.contains("super-secret-token"), "{rendered}");
        assert!(!rendered.contains("/home/user"), "{rendered}");
        assert!(rendered.contains(TOKEN_VAR), "names are listed: {rendered}");
    }

    #[test]
    fn a_valid_token_is_kept_verbatim_and_never_trimmed() {
        let settings = settings(&[(TOKEN_VAR, " abc 123 ")]).expect("spaces are printable");
        let token = settings.session_token.expect("token");
        assert_eq!(token.expose_secret(), " abc 123 ");
    }

    #[test]
    fn invalid_tokens_fail_configuration() {
        for bad in [
            "",
            "line\nbreak",
            "carriage\rreturn",
            "trailing-newline\n",
            "tab\tinside",
            "non-ascii-\u{e9}",
            "del\u{7f}",
            "nul\0byte",
        ] {
            assert_eq!(
                settings(&[(TOKEN_VAR, bad)]).expect_err("must fail"),
                ConfigError::InvalidSessionToken,
                "{bad:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_token_that_is_not_utf8_fails_configuration() {
        use std::os::unix::ffi::OsStringExt;

        let env = EnvMap::from_pairs([(
            OsString::from(TOKEN_VAR),
            OsString::from_vec(vec![b'a', 0xff, b'b']),
        )]);
        assert_eq!(
            Settings::from_env_for(&env, false).expect_err("must fail"),
            ConfigError::InvalidSessionToken
        );
    }

    #[test]
    fn token_shape_rule_matches_rusteeros() {
        assert!(token_shape_ok("a"));
        assert!(token_shape_ok(" ~"));
        assert!(!token_shape_ok(""));
        assert!(!token_shape_ok("\u{1f}"));
        assert!(!token_shape_ok("\u{7f}"));
        assert!(!token_shape_ok("caf\u{e9}"));
    }

    #[test]
    fn the_explicit_session_file_is_taken_as_given() {
        let settings = settings(&[(SESSION_FILE_VAR, "/tmp/some/record.json")]).expect("valid");
        assert_eq!(
            settings.session_file.as_deref(),
            Some(Path::new("/tmp/some/record.json"))
        );
    }

    #[test]
    fn an_empty_session_file_variable_is_a_configuration_error() {
        assert_eq!(
            settings(&[(SESSION_FILE_VAR, "")]).expect_err("must fail"),
            ConfigError::EmptySessionFile
        );
    }

    #[test]
    fn default_file_prefers_the_eeroctl_config_dir() {
        let settings = settings(&[
            (EEROCTL_CONFIG_DIR_VAR, "/cfg"),
            (APPDATA_VAR, "/appdata"),
            (HOME_VAR, "/home/user"),
        ])
        .expect("valid");
        assert_eq!(
            settings.default_session_file.as_deref(),
            Some(Path::new("/cfg").join("cookies.json").as_path())
        );
    }

    #[test]
    fn default_file_uses_appdata_only_on_windows() {
        let pairs = [(APPDATA_VAR, "/appdata"), (HOME_VAR, "/home/user")];
        let windows = Settings::from_env_for(&env(&pairs), true).expect("valid");
        assert_eq!(
            windows.default_session_file.as_deref(),
            Some(
                Path::new("/appdata")
                    .join("eeroctl")
                    .join("cookies.json")
                    .as_path()
            )
        );
        let elsewhere = Settings::from_env_for(&env(&pairs), false).expect("valid");
        assert_eq!(
            elsewhere.default_session_file.as_deref(),
            Some(
                Path::new("/home/user")
                    .join(".config")
                    .join("eeroctl")
                    .join("cookies.json")
                    .as_path()
            )
        );
    }

    #[test]
    fn default_file_falls_back_to_home_when_appdata_is_missing_on_windows() {
        let settings =
            Settings::from_env_for(&env(&[(HOME_VAR, "/home/user")]), true).expect("valid");
        assert!(
            settings
                .default_session_file
                .expect("home fallback")
                .ends_with(Path::new(".config").join("eeroctl").join("cookies.json"))
        );
    }

    #[test]
    fn empty_directory_variables_count_as_unset() {
        let settings = settings(&[
            (EEROCTL_CONFIG_DIR_VAR, ""),
            (APPDATA_VAR, ""),
            (HOME_VAR, ""),
        ])
        .expect("valid");
        assert!(settings.default_session_file.is_none());
    }

    #[test]
    fn the_explicit_file_does_not_remove_default_discovery_data() {
        let settings =
            settings(&[(SESSION_FILE_VAR, "/x.json"), (HOME_VAR, "/home/user")]).expect("valid");
        assert!(settings.session_file.is_some());
        assert!(settings.default_session_file.is_some());
    }

    #[test]
    fn api_base_url_accepts_https_and_loopback_http() {
        for good in [
            "https://api-user.e2ro.com",
            "https://example.test:8443/base",
            "HTTPS://Example.Test",
            "http://localhost",
            "http://localhost:8089",
            "http://LOCALHOST:8089",
            "http://127.0.0.1:8089",
            "http://[::1]:8089",
            "http://[0:0:0:0:0:0:0:1]:8089/",
        ] {
            assert!(api_base_url_allowed(good), "{good}");
            assert_eq!(
                settings(&[(API_BASE_URL_VAR, good)])
                    .expect("accepted")
                    .api_base_url
                    .as_deref(),
                Some(good)
            );
        }
    }

    #[test]
    fn api_base_url_rejects_everything_else() {
        for bad in [
            "",
            "not a url",
            "api-user.e2ro.com",
            "http://example.test",
            "http://api-user.e2ro.com",
            "http://127.0.0.2:8089",
            "http://127.0.0.1.example.test",
            "http://localhost.example.test",
            "http://localhost.:8089",
            "http://10.0.0.1:8089",
            "http://[::2]:8089",
            "http://0.0.0.0:8089",
            "ftp://localhost",
            "file:///tmp/x",
            "http://user:pw@localhost:8089",
            "https://user@example.test",
            "https://example.test/?q=1",
            "https://example.test/#frag",
            "http://localhost:80@evil.test/",
            "http://evil.test\\@localhost/",
        ] {
            assert!(!api_base_url_allowed(bad), "{bad}");
            assert_eq!(
                settings(&[(API_BASE_URL_VAR, bad)]).expect_err("rejected"),
                ConfigError::InvalidApiBaseUrl,
                "{bad}"
            );
        }
    }

    #[test]
    fn config_error_messages_name_variables_but_never_values() {
        let secret = "s3cret-value-that-must-not-leak";
        let error = settings(&[(API_BASE_URL_VAR, secret)]).expect_err("rejected");
        let text = error.to_string();
        assert!(text.contains(API_BASE_URL_VAR));
        assert!(!text.contains(secret));
        let token_error = settings(&[(TOKEN_VAR, "bad\ntoken")]).expect_err("rejected");
        assert!(!token_error.to_string().contains("bad"));
    }

    /// An absolute path on every platform.
    fn abs(tail: &str) -> PathBuf {
        let root = if cfg!(windows) { r"C:\" } else { "/" };
        PathBuf::from(root).join(tail)
    }

    fn own_file(pairs: &[(&str, &str)], windows: bool) -> Result<Option<PathBuf>, ConfigError> {
        Settings::from_env_for(&env(pairs), windows).map(|settings| settings.own_file)
    }

    #[test]
    fn the_own_directory_prefers_the_config_dir_variable() {
        let config = abs("cfg");
        let appdata = abs("appdata");
        let xdg = abs("xdg");
        let found = own_file(
            &[
                (CONFIG_DIR_VAR, config.to_str().expect("utf-8")),
                (APPDATA_VAR, appdata.to_str().expect("utf-8")),
                (XDG_CONFIG_HOME_VAR, xdg.to_str().expect("utf-8")),
                (HOME_VAR, "/home/user"),
            ],
            true,
        )
        .expect("valid");
        assert_eq!(found, Some(config.join("session.json")));
    }

    #[test]
    fn the_own_directory_uses_appdata_only_on_windows() {
        let appdata = abs("appdata");
        let pairs = [
            (APPDATA_VAR, appdata.to_str().expect("utf-8")),
            (HOME_VAR, "/home/user"),
        ];
        assert_eq!(
            own_file(&pairs, true).expect("valid"),
            Some(appdata.join("eero-mcp").join("session.json"))
        );
        assert_eq!(
            own_file(&pairs, false).expect("valid"),
            Some(
                Path::new("/home/user")
                    .join(".config")
                    .join("eero-mcp")
                    .join("session.json")
            )
        );
        // Windows without APPDATA falls through to the next rule.
        assert!(
            own_file(&[(HOME_VAR, "/home/user")], true)
                .expect("valid")
                .expect("home fallback")
                .ends_with(Path::new(".config").join("eero-mcp").join("session.json"))
        );
    }

    #[test]
    fn the_own_directory_honours_an_absolute_xdg_config_home_only() {
        let xdg = abs("xdg");
        assert_eq!(
            own_file(
                &[
                    (XDG_CONFIG_HOME_VAR, xdg.to_str().expect("utf-8")),
                    (HOME_VAR, "/home/user"),
                ],
                false
            )
            .expect("valid"),
            Some(xdg.join("eero-mcp").join("session.json"))
        );
        // A relative value is ignored, per the XDG base-directory rule, and so is an empty one.
        for ignored in ["relative/path", ""] {
            assert!(
                own_file(
                    &[(XDG_CONFIG_HOME_VAR, ignored), (HOME_VAR, "/home/user")],
                    false
                )
                .expect("valid")
                .expect("home fallback")
                .ends_with(Path::new(".config").join("eero-mcp").join("session.json")),
                "{ignored:?}"
            );
        }
    }

    #[test]
    fn there_is_no_own_file_without_any_base_directory() {
        assert_eq!(own_file(&[], false).expect("valid"), None);
        assert_eq!(
            own_file(&[(HOME_VAR, ""), (XDG_CONFIG_HOME_VAR, "")], false).expect("valid"),
            None
        );
    }

    #[test]
    fn an_empty_or_relative_config_dir_is_a_configuration_error() {
        for bad in ["", "relative/dir", "./dir", "~"] {
            assert_eq!(
                own_file(&[(CONFIG_DIR_VAR, bad), (HOME_VAR, "/home/user")], false)
                    .expect_err("must fail"),
                ConfigError::InvalidConfigDir,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_keyring_switch_accepts_only_one() {
        assert!(settings(&[]).expect("valid").keyring_enabled);
        assert!(
            !settings(&[(NO_KEYRING_VAR, "1")])
                .expect("valid")
                .keyring_enabled
        );
        for bad in ["", "0", "true", "yes", "11", " 1"] {
            assert_eq!(
                settings(&[(NO_KEYRING_VAR, bad)]).expect_err("must fail"),
                ConfigError::InvalidNoKeyring,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_own_keyring_names_are_not_the_shared_ones() {
        assert_eq!(OWN_KEYRING_SERVICE, "eero-mcp");
        assert_eq!(OWN_KEYRING_ACCOUNT, "auth-tokens");
        assert_eq!(OWN_FILE_NAME, "session.json");
        assert_ne!(OWN_KEYRING_SERVICE, "eero-api");
    }

    #[test]
    fn the_new_configuration_errors_name_variables_but_never_values() {
        let secret = "relative/s3cret-dir";
        let error = settings(&[(CONFIG_DIR_VAR, secret)]).expect_err("rejected");
        assert!(error.to_string().contains(CONFIG_DIR_VAR));
        assert!(!error.to_string().contains(secret));
        let error = settings(&[(NO_KEYRING_VAR, "s3cret")]).expect_err("rejected");
        assert!(error.to_string().contains(NO_KEYRING_VAR));
        assert!(!error.to_string().contains("s3cret"));
    }

    #[test]
    fn from_process_copies_only_the_known_variables() {
        let captured = EnvMap::from_process();
        for name in captured.0.keys() {
            let name = name.to_str().expect("known names are UTF-8");
            assert!(VARS.contains(&name), "{name} must not be captured");
        }
        // PATH is set in every environment this test can run in, and must not be captured.
        assert!(captured.get("PATH").is_none());
    }
}
