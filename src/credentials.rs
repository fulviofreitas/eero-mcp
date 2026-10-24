//! The read-only credential resolution chain.
//!
//! First hit wins:
//!
//! 1. `RUSTEERO_SESSION_TOKEN`, validated by [`crate::config`] and held in [`CredentialChain`];
//! 2. the shared OS keyring entry (service `eero-api`, account `auth-tokens`), builds with the
//!    `keyring` feature only: a raw, read-only entry read parsed by rusteero's pure record parser;
//! 3. a credential-record file: `EERO_MCP_SESSION_FILE`, else eeroctl's default `cookies.json`;
//! 4. nothing: the server starts unauthenticated.
//!
//! eero-mcp never writes, migrates, promotes or deletes a credential. rusteero's keyring, file and
//! chained credential stores are not used, because each can write (a legacy record is rewritten
//! in place, a fallback hit is promoted and its source deleted); the keyring blob and the file are
//! both parsed by `Session::from_json`, which never writes.
//!
//! A source is a hit only when it yields a non-empty token that passes the token-shape rule. An
//! empty session or a malformed token is a miss, never a hit, so a cleared keyring entry never
//! shadows a valid file.
//!
//! Every source is injectable ([`Sources`]), so tests never touch the real keyring or the user's
//! eeroctl file. Reads are blocking; [`Resolver::reread`] runs them on tokio's blocking pool.
//! Nothing here logs a secret, a credential blob or a file path.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusteero::Session;
use secrecy::{ExposeSecret, SecretString};

use crate::config::{Settings, token_shape_ok};

/// The largest credential record read from a file, in bytes. Real records are a few hundred
/// bytes; the bound keeps a hostile or mistaken `EERO_MCP_SESSION_FILE` (a huge file, `/dev/zero`)
/// from exhausting memory.
pub const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// What the keyring read found. The record holds a live token, so it is a secret: `Debug` never
/// prints it.
#[derive(Clone)]
pub enum KeyringRead {
    /// The stored record (a JSON blob).
    Record(SecretString),
    /// No entry.
    Missing,
    /// The keyring could not be used (no Secret Service, locked, platform error, not compiled
    /// in). Treated as a miss.
    Unavailable,
}

impl KeyringRead {
    /// A found record.
    pub fn record(text: impl Into<String>) -> Self {
        Self::Record(SecretString::from(text.into()))
    }
}

impl PartialEq for KeyringRead {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Record(a), Self::Record(b)) => a.expose_secret() == b.expose_secret(),
            (Self::Missing, Self::Missing) | (Self::Unavailable, Self::Unavailable) => true,
            _ => false,
        }
    }
}

impl Eq for KeyringRead {}

impl fmt::Debug for KeyringRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record(record) => {
                write!(
                    f,
                    "Record(<redacted, {} bytes>)",
                    record.expose_secret().len()
                )
            }
            Self::Missing => f.write_str("Missing"),
            Self::Unavailable => f.write_str("Unavailable"),
        }
    }
}

/// What reading a credential-record file found. The content holds a live token, so it is a
/// secret: `Debug` never prints it.
#[derive(Clone)]
pub enum FileRead {
    /// The file content.
    Content(SecretString),
    /// The file does not exist.
    Absent,
    /// The file exists, or could not be inspected, but cannot be read: not a regular file, not
    /// valid UTF-8, or larger than [`MAX_RECORD_BYTES`].
    Unreadable,
}

impl FileRead {
    /// A file with this content.
    pub fn content(text: impl Into<String>) -> Self {
        Self::Content(SecretString::from(text.into()))
    }
}

impl PartialEq for FileRead {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Content(a), Self::Content(b)) => a.expose_secret() == b.expose_secret(),
            (Self::Absent, Self::Absent) | (Self::Unreadable, Self::Unreadable) => true,
            _ => false,
        }
    }
}

impl Eq for FileRead {}

impl fmt::Debug for FileRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Content(content) => {
                write!(
                    f,
                    "Content(<redacted, {} bytes>)",
                    content.expose_secret().len()
                )
            }
            Self::Absent => f.write_str("Absent"),
            Self::Unreadable => f.write_str("Unreadable"),
        }
    }
}

/// The raw credential sources, injectable for tests. Implementations only read.
pub trait Sources: Send + Sync + 'static {
    /// Reads the shared keyring entry.
    fn keyring_record(&self) -> KeyringRead;
    /// Reads a credential-record file.
    fn read_file(&self, path: &Path) -> FileRead;
}

/// The real sources: the OS keyring (with the `keyring` feature) and the file system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSources;

impl Sources for SystemSources {
    #[cfg(feature = "keyring")]
    fn keyring_record(&self) -> KeyringRead {
        use rusteero::storage::keyring::{ACCOUNT_NAME, SERVICE_NAME};

        let Ok(entry) = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME) else {
            return KeyringRead::Unavailable;
        };
        match entry.get_password() {
            Ok(record) => KeyringRead::record(record),
            Err(keyring::Error::NoEntry) => KeyringRead::Missing,
            Err(_) => KeyringRead::Unavailable,
        }
    }

    #[cfg(not(feature = "keyring"))]
    fn keyring_record(&self) -> KeyringRead {
        KeyringRead::Unavailable
    }

    fn read_file(&self, path: &Path) -> FileRead {
        use std::io::Read as _;

        let failure = |error: &std::io::Error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                FileRead::Absent
            } else {
                FileRead::Unreadable
            }
        };
        // Only a regular file is opened: opening a FIFO would park the blocking pool forever.
        match std::fs::metadata(path) {
            Ok(metadata) if !metadata.is_file() => return FileRead::Unreadable,
            Err(error) => return failure(&error),
            Ok(_) => {}
        }
        let file = match std::fs::File::open(path) {
            Ok(file) => file,
            Err(error) => return failure(&error),
        };
        let mut content = String::new();
        match file.take(MAX_RECORD_BYTES + 1).read_to_string(&mut content) {
            Ok(_)
                if u64::try_from(content.len()).is_ok_and(|length| length <= MAX_RECORD_BYTES) =>
            {
                FileRead::content(content)
            }
            _ => FileRead::Unreadable,
        }
    }
}

/// A failed startup resolution. The messages carry no secret and no path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupError {
    /// `EERO_MCP_SESSION_FILE` is set but the file cannot be read.
    SessionFileUnreadable,
    /// `EERO_MCP_SESSION_FILE` is set but its content is not a credential record.
    SessionFileUnparsable,
    /// `EERO_MCP_SESSION_FILE` is set and the resolution task failed (it panicked), so the
    /// configured file may not have been read: startup fails rather than ignore it.
    ResolutionFailed,
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SessionFileUnreadable => "EERO_MCP_SESSION_FILE is set but cannot be read",
            Self::SessionFileUnparsable => {
                "EERO_MCP_SESSION_FILE is set but is not a valid credential record"
            }
            Self::ResolutionFailed => {
                "credential resolution failed unexpectedly while EERO_MCP_SESSION_FILE is set"
            }
        })
    }
}

impl std::error::Error for StartupError {}

/// The record parsed and was rejected by rusteero's parser.
struct Unparsable;

/// Parses a credential record with rusteero's pure parser. `Ok(None)` is a record with no usable
/// token (an empty session, or a token that fails the shape rule): a miss.
fn token_from_record(record: &str) -> Result<Option<SecretString>, Unparsable> {
    let session = Session::from_json(record).map_err(|_| Unparsable)?;
    let token = session.token();
    Ok(token_shape_ok(token.expose_secret()).then(|| token.clone()))
}

/// The resolution chain over [`Sources`].
pub struct CredentialChain {
    env_token: Option<SecretString>,
    explicit_file: Option<PathBuf>,
    default_file: Option<PathBuf>,
    sources: Arc<dyn Sources>,
}

impl fmt::Debug for CredentialChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialChain")
            .field("env_token", &self.env_token.is_some())
            .field("explicit_file", &self.explicit_file.is_some())
            .field("default_file", &self.default_file.is_some())
            .finish_non_exhaustive()
    }
}

impl CredentialChain {
    /// A chain over `settings` and the given sources.
    pub fn new(settings: &Settings, sources: Arc<dyn Sources>) -> Self {
        Self {
            env_token: settings.session_token.clone(),
            explicit_file: settings.session_file.clone(),
            default_file: settings.default_session_file.clone(),
            sources,
        }
    }

    /// A chain over `settings` and the real sources.
    pub fn from_settings(settings: &Settings) -> Self {
        Self::new(settings, Arc::new(SystemSources))
    }

    /// Whether `EERO_MCP_SESSION_FILE` is configured: that source must never be silently skipped.
    pub fn has_explicit_file(&self) -> bool {
        self.explicit_file.is_some()
    }

    /// Resolves the credential at startup. An unreadable or unparsable explicit file is an
    /// error; everything else that is not a hit is a miss.
    pub fn startup(&self) -> Result<Option<SecretString>, StartupError> {
        self.resolve(true)
    }

    /// Re-resolves the credential after an authentication failure. Every source error counts as
    /// a miss, including an unreadable or unparsable explicit file: nothing fails the process.
    pub fn reread(&self) -> Option<SecretString> {
        self.resolve(false).unwrap_or_else(|_| {
            // Unreachable: with `strict` off, `resolve` never returns an error.
            tracing::warn!("credential re-read failed unexpectedly");
            None
        })
    }

    /// The chain. `strict` makes an explicit file failure an error (startup) rather than a miss
    /// (re-read).
    fn resolve(&self, strict: bool) -> Result<Option<SecretString>, StartupError> {
        // 1. RUSTEERO_SESSION_TOKEN (validated by the configuration).
        if let Some(token) = &self.env_token {
            return Ok(Some(token.clone()));
        }

        // 2. The shared OS keyring entry, read-only (keyring builds only).
        if cfg!(feature = "keyring") {
            match self.sources.keyring_record() {
                KeyringRead::Record(record) => match token_from_record(record.expose_secret()) {
                    Ok(Some(token)) => return Ok(Some(token)),
                    Ok(None) => tracing::debug!("keyring entry holds no usable token; skipped"),
                    Err(Unparsable) => {
                        tracing::debug!("keyring entry is not a credential record; skipped");
                    }
                },
                KeyringRead::Missing => tracing::debug!("no keyring entry; skipped"),
                KeyringRead::Unavailable => tracing::debug!("keyring unavailable; skipped"),
            }
        }

        // 3. A credential-record file.
        if let Some(path) = &self.explicit_file {
            return self.read_explicit_file(path, strict);
        }
        if let Some(path) = &self.default_file {
            return Ok(self.read_default_file(path));
        }

        // 4. Nothing.
        Ok(None)
    }

    fn read_explicit_file(
        &self,
        path: &Path,
        strict: bool,
    ) -> Result<Option<SecretString>, StartupError> {
        let failure = match self.sources.read_file(path) {
            FileRead::Content(content) => match token_from_record(content.expose_secret()) {
                Ok(Some(token)) => return Ok(Some(token)),
                Ok(None) => {
                    tracing::debug!("EERO_MCP_SESSION_FILE holds no usable token; skipped");
                    return Ok(None);
                }
                Err(Unparsable) => StartupError::SessionFileUnparsable,
            },
            FileRead::Absent | FileRead::Unreadable => StartupError::SessionFileUnreadable,
        };
        if strict {
            Err(failure)
        } else {
            tracing::warn!("{failure}; treated as a miss during a credential re-read");
            Ok(None)
        }
    }

    fn read_default_file(&self, path: &Path) -> Option<SecretString> {
        match self.sources.read_file(path) {
            FileRead::Content(content) => match token_from_record(content.expose_secret()) {
                Ok(Some(token)) => Some(token),
                Ok(None) => {
                    tracing::debug!("eeroctl credential file holds no usable token; skipped");
                    None
                }
                Err(Unparsable) => {
                    tracing::warn!("eeroctl credential file is not a valid credential record");
                    None
                }
            },
            FileRead::Absent => {
                tracing::debug!("no eeroctl credential file; skipped");
                None
            }
            FileRead::Unreadable => {
                tracing::warn!("eeroctl credential file cannot be read");
                None
            }
        }
    }
}

/// Something that can re-read the credential chain (blocking).
pub trait Resolve: Send + Sync + 'static {
    /// Re-runs the resolution chain once. Every error is a miss.
    fn reread(&self) -> Option<SecretString>;
}

impl Resolve for CredentialChain {
    fn reread(&self) -> Option<SecretString> {
        CredentialChain::reread(self)
    }
}

/// The binary shares one chain between the startup resolution and the re-reader.
impl Resolve for Arc<CredentialChain> {
    fn reread(&self) -> Option<SecretString> {
        CredentialChain::reread(self)
    }
}

/// The credential re-reader the server holds. Cheap to clone.
#[derive(Clone)]
pub struct Resolver(Arc<dyn Resolve>);

struct FromFn<F>(F);

impl<F> Resolve for FromFn<F>
where
    F: Fn() -> Option<String> + Send + Sync + 'static,
{
    fn reread(&self) -> Option<SecretString> {
        (self.0)().map(SecretString::from)
    }
}

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver").finish_non_exhaustive()
    }
}

impl Resolver {
    /// A resolver over any [`Resolve`] implementation.
    pub fn new(resolve: impl Resolve) -> Self {
        Self(Arc::new(resolve))
    }

    /// A resolver over the real chain.
    pub fn from_chain(chain: CredentialChain) -> Self {
        Self::new(chain)
    }

    /// A fake resolver that calls `f` on every re-read (tests).
    pub fn from_fn(f: impl Fn() -> Option<String> + Send + Sync + 'static) -> Self {
        Self::new(FromFn(f))
    }

    /// A fake resolver that always yields `token` (tests). `Resolver::fixed(None)` finds nothing
    /// new on a re-read.
    pub fn fixed(token: Option<&str>) -> Self {
        let token = token.map(str::to_owned);
        Self::from_fn(move || token.clone())
    }

    /// A fake resolver that yields the given tokens in order, then the last one forever (tests).
    pub fn sequence<I, S>(tokens: I) -> Self
    where
        I: IntoIterator<Item = Option<S>>,
        S: Into<String>,
    {
        let tokens: Vec<Option<String>> = tokens
            .into_iter()
            .map(|token| token.map(Into::into))
            .collect();
        let next = std::sync::atomic::AtomicUsize::new(0);
        Self::from_fn(move || {
            let index = next.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokens
                .get(index)
                .or_else(|| tokens.last())
                .cloned()
                .flatten()
        })
    }

    /// Re-reads the chain on tokio's blocking pool, so a slow or prompting keyring never stalls
    /// the async runtime. A failed blocking task counts as a miss.
    pub async fn reread(&self) -> Option<SecretString> {
        let resolve = Arc::clone(&self.0);
        let Ok(token) = tokio::task::spawn_blocking(move || resolve.reread()).await else {
            tracing::warn!("credential re-read task failed; treated as a miss");
            return None;
        };
        token
    }
}

/// Resolves the credential at startup on tokio's blocking pool.
///
/// If the resolution task itself fails (a panic in a keyring backend, say) and
/// `EERO_MCP_SESSION_FILE` is configured, startup fails: a configured source must not be silently
/// ignored. Without an explicit file every source is best-effort, so the server starts without a
/// credential (a later call re-reads the sources).
pub async fn resolve_at_startup(
    chain: Arc<CredentialChain>,
) -> Result<Option<SecretString>, StartupError> {
    let explicit_file = chain.has_explicit_file();
    match tokio::task::spawn_blocking(move || chain.startup()).await {
        Ok(result) => result,
        Err(_) if explicit_file => Err(StartupError::ResolutionFailed),
        Err(_) => {
            tracing::warn!("credential resolution task failed; continuing without a credential");
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::config::{EnvMap, Settings};

    /// Fake sources: a keyring answer and a map of files. Records every file read.
    struct Fake {
        keyring: KeyringRead,
        files: HashMap<PathBuf, FileRead>,
        reads: Mutex<Vec<PathBuf>>,
        keyring_calls: Mutex<usize>,
    }

    impl Fake {
        fn new(keyring: KeyringRead) -> Self {
            Self {
                keyring,
                files: HashMap::new(),
                reads: Mutex::new(Vec::new()),
                keyring_calls: Mutex::new(0),
            }
        }

        fn with_file(mut self, path: impl Into<PathBuf>, read: FileRead) -> Self {
            self.files.insert(path.into(), read);
            self
        }
    }

    impl Sources for Fake {
        fn keyring_record(&self) -> KeyringRead {
            *self.keyring_calls.lock().expect("lock") += 1;
            self.keyring.clone()
        }

        fn read_file(&self, path: &Path) -> FileRead {
            self.reads.lock().expect("lock").push(path.to_path_buf());
            self.files.get(path).cloned().unwrap_or(FileRead::Absent)
        }
    }

    fn record(token: &str) -> String {
        format!(r#"{{"session_id":"{token}","schema_version":2}}"#)
    }

    const EXPLICIT: &str = "/explicit/record.json";
    /// eeroctl's default file for `HOME=/home/user`, built the way the configuration builds it so
    /// the comparison holds with either path separator.
    fn default_file() -> PathBuf {
        Path::new("/home/user")
            .join(".config")
            .join("eeroctl")
            .join("cookies.json")
    }

    fn chain(pairs: &[(&str, &str)], fake: Fake) -> CredentialChain {
        let settings = Settings::from_env_for(&EnvMap::from_pairs(pairs.iter().copied()), false)
            .expect("valid settings");
        CredentialChain::new(&settings, Arc::new(fake))
    }

    fn expose(token: Option<SecretString>) -> Option<String> {
        token.map(|token| token.expose_secret().to_owned())
    }

    #[test]
    fn nothing_found_yields_none() {
        let chain = chain(&[], Fake::new(KeyringRead::Missing));
        assert_eq!(expose(chain.startup().expect("ok")), None);
    }

    #[test]
    fn the_environment_token_wins_over_every_other_source() {
        let fake = Fake::new(KeyringRead::record(record("from-keyring")))
            .with_file(EXPLICIT, FileRead::content(record("from-file")));
        let chain = chain(
            &[
                ("RUSTEERO_SESSION_TOKEN", "from-env"),
                ("EERO_MCP_SESSION_FILE", EXPLICIT),
            ],
            fake,
        );
        assert_eq!(
            expose(chain.startup().expect("ok")).as_deref(),
            Some("from-env")
        );
        assert_eq!(expose(chain.reread()).as_deref(), Some("from-env"));
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn the_keyring_wins_over_files() {
        let fake = Fake::new(KeyringRead::record(record("from-keyring")))
            .with_file(default_file(), FileRead::content(record("from-file")));
        let chain = chain(&[("HOME", "/home/user")], fake);
        assert_eq!(
            expose(chain.startup().expect("ok")).as_deref(),
            Some("from-keyring")
        );
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn keyring_misses_fall_through_to_the_file_silently() {
        for keyring in [
            KeyringRead::Missing,
            KeyringRead::Unavailable,
            KeyringRead::record("not json".to_owned()),
            KeyringRead::record("42".to_owned()),
            KeyringRead::record(r#"{"session_id":null,"schema_version":2}"#.to_owned()),
            KeyringRead::record(r#"{"session_id":"","schema_version":2}"#.to_owned()),
            KeyringRead::record(r"{}".to_owned()),
            KeyringRead::record(record("bad\\ntoken")),
        ] {
            let fake = Fake::new(keyring.clone())
                .with_file(default_file(), FileRead::content(record("from-file")));
            let chain = chain(&[("HOME", "/home/user")], fake);
            assert_eq!(
                expose(chain.startup().expect("never a startup failure")).as_deref(),
                Some("from-file"),
                "{keyring:?}"
            );
        }
    }

    #[cfg(not(feature = "keyring"))]
    #[test]
    fn headless_builds_never_consult_the_keyring() {
        let fake = Fake::new(KeyringRead::record(record("from-keyring")))
            .with_file(default_file(), FileRead::content(record("from-file")));
        let settings = Settings::from_env_for(&EnvMap::from_pairs([("HOME", "/home/user")]), false)
            .expect("valid");
        let fake = Arc::new(fake);
        let chain = CredentialChain::new(&settings, fake.clone());
        assert_eq!(
            expose(chain.startup().expect("ok")).as_deref(),
            Some("from-file")
        );
        assert_eq!(*fake.keyring_calls.lock().expect("lock"), 0);
    }

    #[test]
    fn the_explicit_file_is_used_and_default_discovery_is_skipped() {
        let fake = Fake::new(KeyringRead::Missing)
            .with_file(EXPLICIT, FileRead::content(record("from-explicit")))
            .with_file(default_file(), FileRead::content(record("from-default")));
        let settings = Settings::from_env_for(
            &EnvMap::from_pairs([("EERO_MCP_SESSION_FILE", EXPLICIT), ("HOME", "/home/user")]),
            false,
        )
        .expect("valid");
        let fake = Arc::new(fake);
        let chain = CredentialChain::new(&settings, fake.clone());
        assert_eq!(
            expose(chain.startup().expect("ok")).as_deref(),
            Some("from-explicit")
        );
        assert_eq!(
            *fake.reads.lock().expect("lock"),
            vec![PathBuf::from(EXPLICIT)],
            "the default file is not even read"
        );
    }

    #[test]
    fn the_default_file_is_used_when_no_explicit_file_is_set() {
        let fake = Fake::new(KeyringRead::Missing)
            .with_file(default_file(), FileRead::content(record("from-default")));
        let chain = chain(&[("HOME", "/home/user")], fake);
        assert_eq!(
            expose(chain.startup().expect("ok")).as_deref(),
            Some("from-default")
        );
    }

    #[test]
    fn a_legacy_record_is_accepted_and_read_only() {
        let legacy = r#"{"user_token": "legacy-token", "session_expiry": "2099-01-01T00:00:00"}"#;
        let fake = Fake::new(KeyringRead::Missing)
            .with_file(EXPLICIT, FileRead::content(legacy.to_owned()));
        let chain = chain(&[("EERO_MCP_SESSION_FILE", EXPLICIT)], fake);
        assert_eq!(
            expose(chain.startup().expect("ok")).as_deref(),
            Some("legacy-token")
        );
    }

    #[test]
    fn a_record_with_extra_fields_still_parses() {
        let eeroctl = r#"{"session_id": "eeroctl-token", "refresh_token": null, "session_expiry": "2026-10-11T05:40:51"}"#;
        let fake = Fake::new(KeyringRead::Missing)
            .with_file(EXPLICIT, FileRead::content(eeroctl.to_owned()));
        let chain = chain(&[("EERO_MCP_SESSION_FILE", EXPLICIT)], fake);
        assert_eq!(
            expose(chain.startup().expect("ok")).as_deref(),
            Some("eeroctl-token")
        );
    }

    #[test]
    fn an_empty_record_is_a_miss_not_a_hit_and_not_a_startup_failure() {
        for empty in [
            r#"{"session_id":null,"schema_version":2}"#,
            r#"{"session_id":"","schema_version":2}"#,
            r"{}",
            r#"{"user_token":""}"#,
            r#"{"session_id":"has\nnewline","schema_version":2}"#,
        ] {
            let fake = Fake::new(KeyringRead::Missing)
                .with_file(EXPLICIT, FileRead::content(empty.to_owned()));
            let chain = chain(&[("EERO_MCP_SESSION_FILE", EXPLICIT)], fake);
            assert_eq!(
                expose(chain.startup().expect("explicit empty record is a miss")),
                None,
                "{empty}"
            );
        }
    }

    #[test]
    fn an_empty_keyring_record_does_not_shadow_a_valid_file() {
        let fake = Fake::new(KeyringRead::record(
            r#"{"session_id":null,"schema_version":2}"#.to_owned(),
        ))
        .with_file(default_file(), FileRead::content(record("from-file")));
        let chain = chain(&[("HOME", "/home/user")], fake);
        assert_eq!(
            expose(chain.startup().expect("ok")).as_deref(),
            Some("from-file")
        );
    }

    #[test]
    fn an_unreadable_explicit_file_fails_startup() {
        for read in [FileRead::Unreadable, FileRead::Absent] {
            let fake = Fake::new(KeyringRead::Missing).with_file(EXPLICIT, read);
            let chain = chain(&[("EERO_MCP_SESSION_FILE", EXPLICIT)], fake);
            assert_eq!(
                chain.startup().expect_err("must fail"),
                StartupError::SessionFileUnreadable
            );
        }
    }

    #[test]
    fn an_unparsable_explicit_file_fails_startup() {
        for content in [
            "not json",
            "42",
            "\"just a string\"",
            r#"{"session_id": 7}"#,
            "",
        ] {
            let fake = Fake::new(KeyringRead::Missing)
                .with_file(EXPLICIT, FileRead::content(content.to_owned()));
            let chain = chain(&[("EERO_MCP_SESSION_FILE", EXPLICIT)], fake);
            assert_eq!(
                chain.startup().expect_err("must fail"),
                StartupError::SessionFileUnparsable,
                "{content:?}"
            );
        }
    }

    #[test]
    fn an_explicit_file_failure_does_not_fall_through_to_the_default_file() {
        let fake = Fake::new(KeyringRead::Missing)
            .with_file(EXPLICIT, FileRead::Unreadable)
            .with_file(default_file(), FileRead::content(record("from-default")));
        let chain = chain(
            &[("EERO_MCP_SESSION_FILE", EXPLICIT), ("HOME", "/home/user")],
            fake,
        );
        assert!(chain.startup().is_err());
    }

    #[test]
    fn default_file_problems_are_misses_never_failures() {
        for read in [
            FileRead::Absent,
            FileRead::Unreadable,
            FileRead::content("not json".to_owned()),
            FileRead::content(r#"{"session_id":null,"schema_version":2}"#.to_owned()),
        ] {
            let fake = Fake::new(KeyringRead::Missing).with_file(default_file(), read.clone());
            let chain = chain(&[("HOME", "/home/user")], fake);
            assert_eq!(
                expose(chain.startup().expect("never fails")),
                None,
                "{read:?}"
            );
        }
    }

    #[test]
    fn a_reread_counts_every_source_error_as_a_miss() {
        for read in [
            FileRead::Unreadable,
            FileRead::Absent,
            FileRead::content("not json".to_owned()),
        ] {
            let fake = Fake::new(KeyringRead::Missing).with_file(EXPLICIT, read);
            let chain = chain(&[("EERO_MCP_SESSION_FILE", EXPLICIT)], fake);
            assert_eq!(expose(chain.reread()), None);
        }
    }

    #[test]
    fn a_reread_sees_a_file_that_appeared_after_startup() {
        struct Switch(Mutex<FileRead>);
        impl Sources for Switch {
            fn keyring_record(&self) -> KeyringRead {
                KeyringRead::Missing
            }
            fn read_file(&self, _: &Path) -> FileRead {
                self.0.lock().expect("lock").clone()
            }
        }
        let switch = Arc::new(Switch(Mutex::new(FileRead::Absent)));
        let settings = Settings::from_env_for(&EnvMap::from_pairs([("HOME", "/home/user")]), false)
            .expect("valid");
        let chain = CredentialChain::new(&settings, switch.clone());
        assert_eq!(expose(chain.startup().expect("ok")), None);
        *switch.0.lock().expect("lock") = FileRead::content(record("logged-in-later"));
        assert_eq!(expose(chain.reread()).as_deref(), Some("logged-in-later"));
    }

    #[test]
    fn debug_output_never_contains_a_token() {
        let chain = chain(
            &[("RUSTEERO_SESSION_TOKEN", "super-secret-token")],
            Fake::new(KeyringRead::Missing),
        );
        assert!(!format!("{chain:?}").contains("super-secret-token"));
        assert!(!format!("{:?}", Resolver::fixed(Some("super-secret-token"))).contains("super"));
    }

    #[tokio::test]
    async fn resolver_fixed_and_sequence_behave_as_documented() {
        let fixed = Resolver::fixed(Some("tok"));
        assert_eq!(expose(fixed.reread().await).as_deref(), Some("tok"));
        assert_eq!(expose(fixed.reread().await).as_deref(), Some("tok"));
        assert_eq!(expose(Resolver::fixed(None).reread().await), None);

        let sequence = Resolver::sequence([None, Some("a"), Some("b")]);
        assert_eq!(expose(sequence.reread().await), None);
        assert_eq!(expose(sequence.reread().await).as_deref(), Some("a"));
        assert_eq!(expose(sequence.reread().await).as_deref(), Some("b"));
        assert_eq!(
            expose(sequence.reread().await).as_deref(),
            Some("b"),
            "last repeats"
        );
    }

    #[tokio::test]
    async fn startup_resolution_runs_off_the_async_threads() {
        let fake = Fake::new(KeyringRead::Missing)
            .with_file(EXPLICIT, FileRead::content(record("blocking-pool")));
        let chain = Arc::new(chain(&[("EERO_MCP_SESSION_FILE", EXPLICIT)], fake));
        let token = resolve_at_startup(chain).await.expect("ok");
        assert_eq!(expose(token).as_deref(), Some("blocking-pool"));
    }

    #[test]
    fn raw_reads_never_print_their_content() {
        let secret = "super-secret-session";
        let keyring = KeyringRead::record(record(secret));
        let file = FileRead::content(record(secret));
        for rendered in [format!("{keyring:?}"), format!("{file:?}")] {
            assert!(!rendered.contains(secret), "{rendered}");
            assert!(rendered.contains("redacted"), "{rendered}");
        }
        assert_eq!(keyring, KeyringRead::record(record(secret)));
        assert_ne!(keyring, KeyringRead::record(record("other")));
        assert_ne!(keyring, KeyringRead::Missing);
        assert_eq!(file, FileRead::content(record(secret)));
        assert_ne!(file, FileRead::content(record("other")));
        assert_ne!(file, FileRead::Absent);
        assert_eq!(format!("{:?}", KeyringRead::Missing), "Missing");
        assert_eq!(format!("{:?}", FileRead::Unreadable), "Unreadable");
    }

    /// A source whose every read panics, like a buggy keyring backend.
    struct Panics;

    impl Sources for Panics {
        fn keyring_record(&self) -> KeyringRead {
            panic!("simulated keyring backend bug");
        }

        fn read_file(&self, _: &Path) -> FileRead {
            panic!("simulated file source bug");
        }
    }

    #[tokio::test]
    async fn a_failed_startup_task_fails_closed_when_an_explicit_file_is_configured() {
        let settings = Settings::from_env_for(
            &EnvMap::from_pairs([("EERO_MCP_SESSION_FILE", EXPLICIT)]),
            false,
        )
        .expect("valid");
        let chain = Arc::new(CredentialChain::new(&settings, Arc::new(Panics)));
        assert!(chain.has_explicit_file());
        assert_eq!(
            resolve_at_startup(chain).await.expect_err("fail closed"),
            StartupError::ResolutionFailed
        );
    }

    #[tokio::test]
    async fn a_failed_startup_task_without_an_explicit_file_starts_unauthenticated() {
        let settings = Settings::from_env_for(&EnvMap::from_pairs([("HOME", "/home/user")]), false)
            .expect("valid");
        let chain = Arc::new(CredentialChain::new(&settings, Arc::new(Panics)));
        assert!(!chain.has_explicit_file());
        let token = resolve_at_startup(chain)
            .await
            .expect("best-effort sources");
        assert_eq!(expose(token), None);
    }

    #[tokio::test]
    async fn a_failed_reread_task_is_a_miss() {
        let settings = Settings::from_env_for(
            &EnvMap::from_pairs([("EERO_MCP_SESSION_FILE", EXPLICIT)]),
            false,
        )
        .expect("valid");
        let resolver = Resolver::from_chain(CredentialChain::new(&settings, Arc::new(Panics)));
        assert_eq!(expose(resolver.reread().await), None);
    }

    #[test]
    fn an_oversized_file_is_unreadable_not_loaded() {
        let limit = usize::try_from(MAX_RECORD_BYTES).expect("small");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("big.json");

        // Exactly at the limit is still read.
        let (prefix, suffix) = (r#"{"session_id":""#, r#""}"#);
        let at_limit = format!(
            "{prefix}{}{suffix}",
            "a".repeat(limit - prefix.len() - suffix.len())
        );
        assert_eq!(at_limit.len(), limit);
        std::fs::write(&path, &at_limit).expect("write");
        assert_eq!(SystemSources.read_file(&path), FileRead::content(at_limit));

        // One byte more is not.
        std::fs::write(&path, "x".repeat(limit + 1)).expect("write");
        assert_eq!(SystemSources.read_file(&path), FileRead::Unreadable);
    }

    #[test]
    fn invalid_utf8_is_unreadable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("binary.json");
        std::fs::write(&path, [0xff, 0xfe, 0x00]).expect("write");
        assert_eq!(SystemSources.read_file(&path), FileRead::Unreadable);
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_unreadable_and_never_blocks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("pipe.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo is available");
        assert!(made.success());
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(SystemSources.read_file(&fifo));
        });
        let read = receiver
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the read returned instead of blocking on the pipe");
        assert_eq!(read, FileRead::Unreadable);
    }

    #[test]
    fn system_sources_read_real_files_and_report_absence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let present = dir.path().join("record.json");
        std::fs::write(&present, record("on-disk")).expect("write");
        let sources = SystemSources;
        assert_eq!(
            sources.read_file(&present),
            FileRead::content(record("on-disk"))
        );
        assert_eq!(
            sources.read_file(&dir.path().join("missing.json")),
            FileRead::Absent
        );
        // A directory exists but cannot be read as a file.
        assert_eq!(sources.read_file(dir.path()), FileRead::Unreadable);
    }

    #[test]
    fn startup_error_messages_name_the_variable_but_no_path() {
        for error in [
            StartupError::SessionFileUnreadable,
            StartupError::SessionFileUnparsable,
            StartupError::ResolutionFailed,
        ] {
            let text = error.to_string();
            assert!(text.contains("EERO_MCP_SESSION_FILE"));
            assert!(!text.contains('/'));
        }
    }
}
