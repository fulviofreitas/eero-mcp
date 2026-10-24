//! The read-only credential resolution chain.
//!
//! First hit wins:
//!
//! 1. `RUSTEERO_SESSION_TOKEN`, validated by [`crate::config`] and held in [`CredentialChain`];
//! 2. the explicit credential-record file `EERO_MCP_SESSION_FILE`;
//! 3. eero-mcp's own store, written by the login subcommand and the login tool: first its keyring
//!    entry (service `eero-mcp`, account `auth-tokens`; builds with the `keyring` feature, unless
//!    `EERO_MCP_NO_KEYRING` is 1), then its own `session.json`;
//! 4. the shared OS keyring entry (service `eero-api`, account `auth-tokens`), same conditions;
//! 5. eeroctl's default `cookies.json`;
//! 6. nothing: the server starts unauthenticated.
//!
//! This module never writes, migrates, promotes or deletes a credential. rusteero's keyring, file
//! and chained credential stores are not used to read, because each can write (a legacy record is
//! rewritten in place, a fallback hit is promoted and its source deleted); every keyring blob and
//! file is parsed by `Session::from_json`, which never writes. Only the login module writes, and
//! only eero-mcp's own entry and file.
//!
//! A source is a hit only when it yields a non-empty token that passes the token-shape rule. An
//! empty session or a malformed token is a miss, never a hit, so a cleared entry never shadows a
//! valid later source. An explicit file that cannot be read is a startup failure, but a miss
//! during a re-read; either way a usable record in a later source is found.
//!
//! Every source is injectable ([`Sources`]), so tests never touch the real keyring or the user's
//! files. Reads are blocking; [`Resolver::reread`] runs them on tokio's blocking pool. Nothing
//! here logs a secret, a credential blob or a file path.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusteero::Session;
use secrecy::{ExposeSecret, SecretString};

#[cfg(feature = "keyring")]
use crate::config::{OWN_KEYRING_ACCOUNT, OWN_KEYRING_SERVICE};
use crate::config::{Settings, token_shape_ok};

/// The largest credential record read from a file, in bytes. Real records are a few hundred
/// bytes; the bound keeps a hostile or mistaken `EERO_MCP_SESSION_FILE` (a huge file, `/dev/zero`)
/// from exhausting memory.
pub const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// One step of the resolution chain, by the name the status subcommand prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// `RUSTEERO_SESSION_TOKEN`.
    EnvToken,
    /// `EERO_MCP_SESSION_FILE`.
    ExplicitFile,
    /// eero-mcp's own keyring entry.
    OwnKeyring,
    /// eero-mcp's own session file.
    OwnFile,
    /// The keyring entry shared with eeroctl and eero-api.
    SharedKeyring,
    /// eeroctl's default `cookies.json`.
    EeroctlFile,
}

impl Source {
    /// The fixed, path-free name of the source.
    pub const fn name(self) -> &'static str {
        match self {
            Self::EnvToken => "environment token",
            Self::ExplicitFile => "explicit file",
            Self::OwnKeyring => "eero-mcp keyring",
            Self::OwnFile => "eero-mcp file",
            Self::SharedKeyring => "eero-api keyring",
            Self::EeroctlFile => "eeroctl file",
        }
    }
}

/// Which keyring entry a raw read addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyringEntry {
    /// eero-mcp's own entry (service `eero-mcp`).
    Own,
    /// The entry shared with eeroctl and its sibling clients, service `eero-api`.
    Shared,
}

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
    /// Reads a keyring entry.
    fn keyring_record(&self, entry: KeyringEntry) -> KeyringRead;
    /// Reads a credential-record file.
    fn read_file(&self, path: &Path) -> FileRead;
}

/// The real sources: the OS keyring (with the `keyring` feature) and the file system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemSources;

impl Sources for SystemSources {
    #[cfg(feature = "keyring")]
    fn keyring_record(&self, which: KeyringEntry) -> KeyringRead {
        use rusteero::storage::keyring::{ACCOUNT_NAME, SERVICE_NAME};

        let (service, account) = match which {
            KeyringEntry::Own => (OWN_KEYRING_SERVICE, OWN_KEYRING_ACCOUNT),
            KeyringEntry::Shared => (SERVICE_NAME, ACCOUNT_NAME),
        };
        let Ok(entry) = keyring::Entry::new(service, account) else {
            return KeyringRead::Unavailable;
        };
        match entry.get_password() {
            Ok(record) => KeyringRead::record(record),
            Err(keyring::Error::NoEntry) => KeyringRead::Missing,
            Err(_) => KeyringRead::Unavailable,
        }
    }

    #[cfg(not(feature = "keyring"))]
    fn keyring_record(&self, _which: KeyringEntry) -> KeyringRead {
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

/// What reading one keyring entry came to (before any logging).
enum KeyringTry {
    Token(SecretString),
    /// A record that holds no usable token, or is not a credential record at all.
    Other,
    Missing,
    Unavailable,
}

/// What reading one file came to (before any logging).
enum FileTry {
    Token(SecretString),
    /// A record that holds no usable token.
    NoToken,
    Absent,
    Unreadable,
    Unparsable,
}

/// A hit of the chain: the token and the step that produced it.
#[derive(Clone)]
pub struct Resolved {
    /// The step that yielded the token.
    pub source: Source,
    /// The token.
    pub token: SecretString,
}

impl fmt::Debug for Resolved {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolved")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// What one raw read of a single source found.
#[derive(Clone)]
pub enum Probe {
    /// A usable token.
    Token(SecretString),
    /// The source was read and holds nothing usable (or is not configured).
    Empty,
    /// The source could not be read (an unreachable or disabled keyring, an unreadable or
    /// unparsable file): a copy of a token there cannot be ruled out.
    NotChecked,
}

impl fmt::Debug for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(_) => f.write_str("Token(<redacted>)"),
            Self::Empty => f.write_str("Empty"),
            Self::NotChecked => f.write_str("NotChecked"),
        }
    }
}

/// What one of eero-mcp's own backends holds.
#[derive(Clone)]
pub enum OwnRecord {
    /// A record with a usable token.
    Token(SecretString),
    /// A record that holds no usable token, or cannot be read or parsed. It is eero-mcp's own,
    /// so logout still deletes it.
    Other,
    /// No record.
    Absent,
    /// The backend cannot be consulted: a keyring that is disabled, not compiled in or
    /// unreachable.
    NotChecked,
}

impl OwnRecord {
    /// The usable token, if the record has one.
    pub fn token(&self) -> Option<&SecretString> {
        match self {
            Self::Token(token) => Some(token),
            _ => None,
        }
    }

    /// Whether a record exists (usable or not).
    pub fn exists(&self) -> bool {
        matches!(self, Self::Token(_) | Self::Other)
    }
}

impl fmt::Debug for OwnRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(_) => f.write_str("Token(<redacted>)"),
            Self::Other => f.write_str("Other"),
            Self::Absent => f.write_str("Absent"),
            Self::NotChecked => f.write_str("NotChecked"),
        }
    }
}

/// What eero-mcp's own two backends hold.
#[derive(Debug, Clone)]
pub struct OwnRecords {
    /// The own keyring entry.
    pub keyring: OwnRecord,
    /// The own session file.
    pub file: OwnRecord,
}

/// The resolution chain over [`Sources`].
pub struct CredentialChain {
    env_token: Option<SecretString>,
    explicit_file: Option<PathBuf>,
    own_file: Option<PathBuf>,
    default_file: Option<PathBuf>,
    keyring_enabled: bool,
    sources: Arc<dyn Sources>,
}

impl fmt::Debug for CredentialChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialChain")
            .field("env_token", &self.env_token.is_some())
            .field("explicit_file", &self.explicit_file.is_some())
            .field("own_file", &self.own_file.is_some())
            .field("default_file", &self.default_file.is_some())
            .field("keyring_enabled", &self.keyring_enabled)
            .finish_non_exhaustive()
    }
}

impl CredentialChain {
    /// A chain over `settings` and the given sources.
    pub fn new(settings: &Settings, sources: Arc<dyn Sources>) -> Self {
        Self {
            env_token: settings.session_token.clone(),
            explicit_file: settings.session_file.clone(),
            own_file: settings.own_file.clone(),
            default_file: settings.default_session_file.clone(),
            keyring_enabled: settings.keyring_enabled,
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

    /// Whether the keyring entries are consulted at all: the `keyring` feature is compiled in and
    /// `EERO_MCP_NO_KEYRING` is not 1.
    pub fn keyring_active(&self) -> bool {
        cfg!(feature = "keyring") && self.keyring_enabled
    }

    /// Resolves the credential at startup. An unreadable or unparsable explicit file is an
    /// error; everything else that is not a hit is a miss.
    pub fn startup(&self) -> Result<Option<SecretString>, StartupError> {
        Ok(self.startup_resolved()?.map(|resolved| resolved.token))
    }

    /// As [`CredentialChain::startup`], with the step that produced the token (the status
    /// subcommand prints it).
    pub fn startup_resolved(&self) -> Result<Option<Resolved>, StartupError> {
        self.resolve(true)
    }

    /// Re-resolves the credential after an authentication failure. Every source error counts as
    /// a miss, including an unreadable or unparsable explicit file: nothing fails the process.
    pub fn reread(&self) -> Option<SecretString> {
        self.reread_resolved().map(|resolved| resolved.token)
    }

    /// As [`CredentialChain::reread`], with the step that produced the token.
    pub fn reread_resolved(&self) -> Option<Resolved> {
        self.resolve(false).unwrap_or_else(|_| {
            // Unreachable: with `strict` off, `resolve` never returns an error.
            tracing::warn!("credential re-read failed unexpectedly");
            None
        })
    }

    /// The chain. `strict` makes an explicit file failure an error (startup) rather than a miss
    /// (re-read).
    fn resolve(&self, strict: bool) -> Result<Option<Resolved>, StartupError> {
        // 1. RUSTEERO_SESSION_TOKEN (validated by the configuration).
        if let Some(token) = &self.env_token {
            return Ok(Some(Resolved {
                source: Source::EnvToken,
                token: token.clone(),
            }));
        }

        // 2. The explicit credential file.
        if let Some(path) = &self.explicit_file {
            let failure = match self.try_file(path) {
                FileTry::Token(token) => {
                    return Ok(Some(Resolved {
                        source: Source::ExplicitFile,
                        token,
                    }));
                }
                FileTry::NoToken => {
                    tracing::debug!("EERO_MCP_SESSION_FILE holds no usable token; skipped");
                    None
                }
                FileTry::Absent | FileTry::Unreadable => Some(StartupError::SessionFileUnreadable),
                FileTry::Unparsable => Some(StartupError::SessionFileUnparsable),
            };
            if let Some(failure) = failure {
                if strict {
                    return Err(failure);
                }
                tracing::warn!("{failure}; treated as a miss during a credential re-read");
            }
        }

        // 3a. eero-mcp's own keyring entry, 3b. eero-mcp's own file.
        if let Some(resolved) = self.own_store_hit() {
            return Ok(Some(resolved));
        }

        // 4. The shared OS keyring entry, read-only (keyring builds only).
        if self.keyring_active()
            && let Some(token) = self.keyring_hit(KeyringEntry::Shared, "shared keyring entry")
        {
            return Ok(Some(Resolved {
                source: Source::SharedKeyring,
                token,
            }));
        }

        // 5. eeroctl's default credential file.
        if let Some(path) = &self.default_file
            && let Some(token) = self.default_file_hit(path)
        {
            return Ok(Some(Resolved {
                source: Source::EeroctlFile,
                token,
            }));
        }

        // 6. Nothing.
        Ok(None)
    }

    /// Steps 3a and 3b: the first usable token of eero-mcp's own store, with its source.
    fn own_store_hit(&self) -> Option<Resolved> {
        if self.keyring_active()
            && let Some(token) = self.keyring_hit(KeyringEntry::Own, "eero-mcp keyring entry")
        {
            return Some(Resolved {
                source: Source::OwnKeyring,
                token,
            });
        }
        let path = self.own_file.as_deref()?;
        let token = match self.try_file(path) {
            FileTry::Token(token) => Some(token),
            FileTry::NoToken => {
                tracing::debug!("eero-mcp session file holds no usable token; skipped");
                None
            }
            FileTry::Absent => {
                tracing::debug!("no eero-mcp session file; skipped");
                None
            }
            FileTry::Unreadable | FileTry::Unparsable => {
                tracing::warn!(
                    "eero-mcp session file cannot be read or is not a credential record"
                );
                None
            }
        };
        token.map(|token| Resolved {
            source: Source::OwnFile,
            token,
        })
    }

    /// The first usable token of eero-mcp's own store, steps 3a and 3b, without its source.
    pub fn own_store_token(&self) -> Option<SecretString> {
        self.own_store_hit().map(|resolved| resolved.token)
    }

    /// The step that yields a token right now (re-read semantics, no check of the token with
    /// eero), if any.
    pub fn would_use(&self) -> Option<Source> {
        self.reread_resolved().map(|resolved| resolved.source)
    }

    /// The source among steps 1 and 2 that holds a usable token, if any: such a source wins over
    /// eero-mcp's own store, so a fresh login does not take effect while it is configured.
    pub fn higher_precedence_source(&self) -> Option<Source> {
        if self.env_token.is_some() {
            return Some(Source::EnvToken);
        }
        let path = self.explicit_file.as_deref()?;
        matches!(self.try_file(path), FileTry::Token(_)).then_some(Source::ExplicitFile)
    }

    /// What eero-mcp's own two backends hold, read raw (no store, no migration).
    pub fn own_records(&self) -> OwnRecords {
        let keyring = if self.keyring_active() {
            match self.try_keyring(KeyringEntry::Own) {
                KeyringTry::Token(token) => OwnRecord::Token(token),
                KeyringTry::Other => OwnRecord::Other,
                KeyringTry::Missing => OwnRecord::Absent,
                KeyringTry::Unavailable => OwnRecord::NotChecked,
            }
        } else {
            OwnRecord::NotChecked
        };
        let file = match self.own_file.as_deref() {
            None => OwnRecord::Absent,
            Some(path) => match self.try_file(path) {
                FileTry::Token(token) => OwnRecord::Token(token),
                FileTry::NoToken | FileTry::Unreadable | FileTry::Unparsable => OwnRecord::Other,
                FileTry::Absent => OwnRecord::Absent,
            },
        };
        OwnRecords { keyring, file }
    }

    /// One raw read of a single source.
    pub fn probe(&self, source: Source) -> Probe {
        match source {
            Source::EnvToken => self.env_token.clone().map_or(Probe::Empty, Probe::Token),
            Source::ExplicitFile => self
                .explicit_file
                .as_deref()
                .map_or(Probe::Empty, |path| self.probe_file(path)),
            Source::OwnFile => self
                .own_file
                .as_deref()
                .map_or(Probe::Empty, |path| self.probe_file(path)),
            Source::EeroctlFile => self
                .default_file
                .as_deref()
                .map_or(Probe::Empty, |path| self.probe_file(path)),
            Source::OwnKeyring => self.probe_keyring(KeyringEntry::Own),
            Source::SharedKeyring => self.probe_keyring(KeyringEntry::Shared),
        }
    }

    fn probe_file(&self, path: &Path) -> Probe {
        match self.try_file(path) {
            FileTry::Token(token) => Probe::Token(token),
            FileTry::NoToken | FileTry::Absent => Probe::Empty,
            FileTry::Unreadable | FileTry::Unparsable => Probe::NotChecked,
        }
    }

    fn probe_keyring(&self, entry: KeyringEntry) -> Probe {
        if !self.keyring_active() {
            return Probe::NotChecked;
        }
        match self.try_keyring(entry) {
            KeyringTry::Token(token) => Probe::Token(token),
            KeyringTry::Other | KeyringTry::Missing => Probe::Empty,
            KeyringTry::Unavailable => Probe::NotChecked,
        }
    }

    fn try_keyring(&self, entry: KeyringEntry) -> KeyringTry {
        match self.sources.keyring_record(entry) {
            KeyringRead::Record(record) => match token_from_record(record.expose_secret()) {
                Ok(Some(token)) => KeyringTry::Token(token),
                Ok(None) | Err(Unparsable) => KeyringTry::Other,
            },
            KeyringRead::Missing => KeyringTry::Missing,
            KeyringRead::Unavailable => KeyringTry::Unavailable,
        }
    }

    /// A keyring entry as a chain step: a token, or a miss with one debug line (no secret, no
    /// path).
    fn keyring_hit(&self, entry: KeyringEntry, label: &str) -> Option<SecretString> {
        match self.try_keyring(entry) {
            KeyringTry::Token(token) => Some(token),
            KeyringTry::Other => {
                tracing::debug!("{label} holds no usable credential record; skipped");
                None
            }
            KeyringTry::Missing => {
                tracing::debug!("no {label}; skipped");
                None
            }
            KeyringTry::Unavailable => {
                tracing::debug!("keyring unavailable ({label}); skipped");
                None
            }
        }
    }

    fn try_file(&self, path: &Path) -> FileTry {
        match self.sources.read_file(path) {
            FileRead::Content(content) => match token_from_record(content.expose_secret()) {
                Ok(Some(token)) => FileTry::Token(token),
                Ok(None) => FileTry::NoToken,
                Err(Unparsable) => FileTry::Unparsable,
            },
            FileRead::Absent => FileTry::Absent,
            FileRead::Unreadable => FileTry::Unreadable,
        }
    }

    fn default_file_hit(&self, path: &Path) -> Option<SecretString> {
        match self.try_file(path) {
            FileTry::Token(token) => Some(token),
            FileTry::NoToken => {
                tracing::debug!("eeroctl credential file holds no usable token; skipped");
                None
            }
            FileTry::Unparsable => {
                tracing::warn!("eeroctl credential file is not a valid credential record");
                None
            }
            FileTry::Absent => {
                tracing::debug!("no eeroctl credential file; skipped");
                None
            }
            FileTry::Unreadable => {
                tracing::warn!("eeroctl credential file cannot be read");
                None
            }
        }
    }

    /// Whether `EERO_MCP_SESSION_FILE` names eero-mcp's own session file. Login and logout refuse
    /// to run when it does: the login would write, and the logout would delete, an explicitly
    /// configured credential. Each path is compared in its canonical form (symlinks followed;
    /// the own file through its directory when it does not exist yet); a path that cannot be
    /// resolved is compared as written, made absolute.
    pub fn explicit_file_is_own_file(&self) -> bool {
        match (&self.explicit_file, &self.own_file) {
            (Some(explicit), Some(own)) => comparable_path(explicit) == comparable_path(own),
            _ => false,
        }
    }
}

/// The form in which two paths are compared for "the same file".
fn comparable_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }
    // The file itself may not exist yet: resolve its directory and re-attach the name.
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name())
        && let Ok(canonical) = std::fs::canonicalize(parent)
    {
        return canonical.join(name);
    }
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
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
    Ok(resolve_at_startup_resolved(chain)
        .await?
        .map(|resolved| resolved.token))
}

/// As [`resolve_at_startup`], with the step that produced the token.
pub async fn resolve_at_startup_resolved(
    chain: Arc<CredentialChain>,
) -> Result<Option<Resolved>, StartupError> {
    let explicit_file = chain.has_explicit_file();
    match tokio::task::spawn_blocking(move || chain.startup_resolved()).await {
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

    /// Fake sources: a shared and an own keyring answer and a map of files. Records every file
    /// read and every keyring read.
    struct Fake {
        keyring: KeyringRead,
        own_keyring: KeyringRead,
        files: HashMap<PathBuf, FileRead>,
        reads: Mutex<Vec<PathBuf>>,
        keyring_calls: Mutex<usize>,
    }

    impl Fake {
        /// `keyring` answers the shared entry; the own entry starts out missing.
        fn new(keyring: KeyringRead) -> Self {
            Self {
                keyring,
                own_keyring: KeyringRead::Missing,
                files: HashMap::new(),
                reads: Mutex::new(Vec::new()),
                keyring_calls: Mutex::new(0),
            }
        }

        fn with_own_keyring(mut self, own: KeyringRead) -> Self {
            self.own_keyring = own;
            self
        }

        fn with_file(mut self, path: impl Into<PathBuf>, read: FileRead) -> Self {
            self.files.insert(path.into(), read);
            self
        }
    }

    impl Sources for Fake {
        fn keyring_record(&self, entry: KeyringEntry) -> KeyringRead {
            *self.keyring_calls.lock().expect("lock") += 1;
            match entry {
                KeyringEntry::Own => self.own_keyring.clone(),
                KeyringEntry::Shared => self.keyring.clone(),
            }
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
            fn keyring_record(&self, _: KeyringEntry) -> KeyringRead {
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

    // ===================== eero-mcp's own store and the six-step order =====================

    /// An absolute own directory on every platform.
    #[cfg(windows)]
    const OWN_DIR: &str = r"C:\own";
    #[cfg(not(windows))]
    const OWN_DIR: &str = "/own";

    /// The own session file, built the way the configuration builds it.
    fn own_file() -> PathBuf {
        Path::new(OWN_DIR).join("session.json")
    }

    const OWN_DIR_ENV: [(&str, &str); 3] = [
        ("EERO_MCP_CONFIG_DIR", OWN_DIR),
        ("HOME", "/home/user"),
        ("EERO_MCP_SESSION_FILE", EXPLICIT),
    ];

    /// A chain with every one of the six sources populated by a different token.
    fn full_fake() -> Fake {
        Fake::new(KeyringRead::record(record("shared-keyring")))
            .with_own_keyring(KeyringRead::record(record("own-keyring")))
            .with_file(EXPLICIT, FileRead::content(record("explicit")))
            .with_file(own_file(), FileRead::content(record("own-file")))
            .with_file(default_file(), FileRead::content(record("eeroctl")))
    }

    fn resolved_name(chain: &CredentialChain) -> Option<(&'static str, String)> {
        chain.startup_resolved().expect("ok").map(|resolved| {
            (
                resolved.source.name(),
                resolved.token.expose_secret().to_owned(),
            )
        })
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn the_six_steps_win_in_order_and_each_hit_names_its_source() {
        let steps = [
            (&OWN_DIR_ENV[..], "explicit file", "explicit"),
            (&OWN_DIR_ENV[..2], "eero-mcp keyring", "own-keyring"),
        ];
        for (env, name, token) in steps {
            let chain = chain(env, full_fake());
            assert_eq!(
                resolved_name(&chain),
                Some((name, token.to_owned())),
                "{name}"
            );
        }
        let with_env = [
            ("RUSTEERO_SESSION_TOKEN", "from-env"),
            ("EERO_MCP_CONFIG_DIR", OWN_DIR),
            ("EERO_MCP_SESSION_FILE", EXPLICIT),
        ];
        assert_eq!(
            resolved_name(&chain(&with_env, full_fake())),
            Some(("environment token", "from-env".to_owned()))
        );
        // No own keyring record: the own file is next.
        let no_own_keyring = Fake::new(KeyringRead::record(record("shared-keyring")))
            .with_file(own_file(), FileRead::content(record("own-file")))
            .with_file(default_file(), FileRead::content(record("eeroctl")));
        assert_eq!(
            resolved_name(&chain(&OWN_DIR_ENV[..2], no_own_keyring)),
            Some(("eero-mcp file", "own-file".to_owned()))
        );
        // Neither own backend: the shared keyring, then eeroctl's file.
        let shared = Fake::new(KeyringRead::record(record("shared-keyring")))
            .with_file(default_file(), FileRead::content(record("eeroctl")));
        assert_eq!(
            resolved_name(&chain(&OWN_DIR_ENV[..2], shared)),
            Some(("eero-api keyring", "shared-keyring".to_owned()))
        );
        let eeroctl = Fake::new(KeyringRead::Missing)
            .with_file(default_file(), FileRead::content(record("eeroctl")));
        assert_eq!(
            resolved_name(&chain(&OWN_DIR_ENV[..2], eeroctl)),
            Some(("eeroctl file", "eeroctl".to_owned()))
        );
        assert_eq!(
            resolved_name(&chain(&OWN_DIR_ENV[..2], Fake::new(KeyringRead::Missing))),
            None
        );
    }

    #[test]
    fn the_source_names_are_the_documented_words() {
        let names: Vec<&str> = [
            Source::EnvToken,
            Source::ExplicitFile,
            Source::OwnKeyring,
            Source::OwnFile,
            Source::SharedKeyring,
            Source::EeroctlFile,
        ]
        .iter()
        .map(|source| source.name())
        .collect();
        assert_eq!(
            names,
            [
                "environment token",
                "explicit file",
                "eero-mcp keyring",
                "eero-mcp file",
                "eero-api keyring",
                "eeroctl file"
            ]
        );
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn the_keyring_switch_skips_both_keyring_entries() {
        let fake = Arc::new(
            Fake::new(KeyringRead::record(record("shared-keyring")))
                .with_own_keyring(KeyringRead::record(record("own-keyring")))
                .with_file(own_file(), FileRead::content(record("own-file"))),
        );
        let settings = Settings::from_env_for(
            &EnvMap::from_pairs([
                ("EERO_MCP_CONFIG_DIR", OWN_DIR),
                ("EERO_MCP_NO_KEYRING", "1"),
            ]),
            false,
        )
        .expect("valid");
        let chain = CredentialChain::new(&settings, fake.clone());
        assert!(!chain.keyring_active());
        assert_eq!(
            resolved_name(&chain),
            Some(("eero-mcp file", "own-file".to_owned()))
        );
        assert_eq!(*fake.keyring_calls.lock().expect("lock"), 0);
        assert!(matches!(
            chain.probe(Source::SharedKeyring),
            Probe::NotChecked
        ));
        assert!(matches!(chain.own_records().keyring, OwnRecord::NotChecked));
    }

    #[cfg(not(feature = "keyring"))]
    #[test]
    fn headless_builds_report_the_keyring_as_not_checked() {
        let chain = chain(&OWN_DIR_ENV[..2], Fake::new(KeyringRead::Missing));
        assert!(!chain.keyring_active());
        assert!(matches!(chain.probe(Source::OwnKeyring), Probe::NotChecked));
        assert!(matches!(chain.own_records().keyring, OwnRecord::NotChecked));
    }

    #[test]
    fn a_logged_out_explicit_file_no_longer_stops_the_search() {
        let logged_out = r#"{"session_id":null,"schema_version":2}"#;
        let fake = Fake::new(KeyringRead::Missing)
            .with_file(EXPLICIT, FileRead::content(logged_out.to_owned()))
            .with_file(default_file(), FileRead::content(record("eeroctl")));
        let chain = chain(
            &[("EERO_MCP_SESSION_FILE", EXPLICIT), ("HOME", "/home/user")],
            fake,
        );
        assert_eq!(
            resolved_name(&chain),
            Some(("eeroctl file", "eeroctl".to_owned()))
        );
    }

    #[test]
    fn a_reread_continues_past_an_unreadable_explicit_file() {
        for read in [
            FileRead::Unreadable,
            FileRead::Absent,
            FileRead::content("not json".to_owned()),
        ] {
            let fake = Fake::new(KeyringRead::Missing)
                .with_file(EXPLICIT, read.clone())
                .with_file(own_file(), FileRead::content(record("own-file")));
            let chain = chain(&OWN_DIR_ENV, fake);
            assert!(chain.startup().is_err(), "{read:?}: startup still fails");
            assert_eq!(
                expose(chain.reread()).as_deref(),
                Some("own-file"),
                "{read:?}: a re-read falls through to the own store"
            );
        }
    }

    #[test]
    fn own_store_misses_fall_through_silently() {
        for own in [
            FileRead::Absent,
            FileRead::Unreadable,
            FileRead::content("not json".to_owned()),
            FileRead::content(r#"{"session_id":null,"schema_version":2}"#.to_owned()),
        ] {
            let fake = Fake::new(KeyringRead::Missing)
                .with_file(own_file(), own.clone())
                .with_file(default_file(), FileRead::content(record("eeroctl")));
            let chain = chain(&OWN_DIR_ENV[..2], fake);
            assert_eq!(
                resolved_name(&chain),
                Some(("eeroctl file", "eeroctl".to_owned())),
                "{own:?}"
            );
        }
    }

    #[test]
    fn own_records_tell_a_token_from_other_records_and_absence() {
        let cases = [
            (FileRead::content(record("t")), "token"),
            (FileRead::content("not json".to_owned()), "other"),
            (
                FileRead::content(r#"{"session_id":null,"schema_version":2}"#.to_owned()),
                "other",
            ),
            (FileRead::Unreadable, "other"),
            (FileRead::Absent, "absent"),
        ];
        for (read, expected) in cases {
            let fake = Fake::new(KeyringRead::Missing).with_file(own_file(), read.clone());
            let records = chain(&OWN_DIR_ENV[..2], fake).own_records();
            let got = match records.file {
                OwnRecord::Token(_) => "token",
                OwnRecord::Other => "other",
                OwnRecord::Absent => "absent",
                OwnRecord::NotChecked => "not checked",
            };
            assert_eq!(got, expected, "{read:?}");
            assert_eq!(records.file.exists(), expected != "absent", "{read:?}");
        }
        // No own directory: there is no own file to hold anything.
        let none = chain(&[], Fake::new(KeyringRead::Missing)).own_records();
        assert!(matches!(none.file, OwnRecord::Absent));
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn own_records_read_the_own_keyring_entry_raw() {
        for (own, expected) in [
            (KeyringRead::record(record("t")), "token"),
            (KeyringRead::record("not json".to_owned()), "other"),
            (KeyringRead::Missing, "absent"),
            (KeyringRead::Unavailable, "not checked"),
        ] {
            let fake = Fake::new(KeyringRead::Missing).with_own_keyring(own.clone());
            let records = chain(&OWN_DIR_ENV[..2], fake).own_records();
            let got = match records.keyring {
                OwnRecord::Token(_) => "token",
                OwnRecord::Other => "other",
                OwnRecord::Absent => "absent",
                OwnRecord::NotChecked => "not checked",
            };
            assert_eq!(got, expected, "{own:?}");
        }
    }

    #[test]
    fn probes_report_a_token_nothing_or_not_checked() {
        let fake = Fake::new(KeyringRead::Missing)
            .with_file(EXPLICIT, FileRead::Unreadable)
            .with_file(default_file(), FileRead::content(record("eeroctl")))
            .with_file(own_file(), FileRead::content(record("own")));
        let configured = chain(
            &[
                ("RUSTEERO_SESSION_TOKEN", "from-env"),
                ("EERO_MCP_SESSION_FILE", EXPLICIT),
                ("EERO_MCP_CONFIG_DIR", OWN_DIR),
                ("HOME", "/home/user"),
            ],
            fake,
        );
        let token = |probe: Probe| match probe {
            Probe::Token(token) => Some(token.expose_secret().to_owned()),
            _ => None,
        };
        assert_eq!(
            token(configured.probe(Source::EnvToken)).as_deref(),
            Some("from-env")
        );
        assert_eq!(
            token(configured.probe(Source::EeroctlFile)).as_deref(),
            Some("eeroctl")
        );
        assert_eq!(
            token(configured.probe(Source::OwnFile)).as_deref(),
            Some("own")
        );
        // An unreadable explicit file cannot be ruled out as a copy holder.
        assert!(matches!(
            configured.probe(Source::ExplicitFile),
            Probe::NotChecked
        ));
        // An unconfigured source holds nothing.
        let bare = chain(&[], Fake::new(KeyringRead::Missing));
        for source in [
            Source::EnvToken,
            Source::ExplicitFile,
            Source::OwnFile,
            Source::EeroctlFile,
        ] {
            assert!(matches!(bare.probe(source), Probe::Empty), "{source:?}");
        }
    }

    #[test]
    fn the_higher_precedence_source_is_a_usable_env_token_or_explicit_file() {
        let usable = chain(
            &[("EERO_MCP_SESSION_FILE", EXPLICIT)],
            Fake::new(KeyringRead::Missing).with_file(EXPLICIT, FileRead::content(record("x"))),
        );
        assert_eq!(
            usable.higher_precedence_source(),
            Some(Source::ExplicitFile)
        );
        let logged_out = chain(
            &[("EERO_MCP_SESSION_FILE", EXPLICIT)],
            Fake::new(KeyringRead::Missing).with_file(
                EXPLICIT,
                FileRead::content(r#"{"session_id":null,"schema_version":2}"#.to_owned()),
            ),
        );
        assert_eq!(logged_out.higher_precedence_source(), None);
        let env = chain(
            &[("RUSTEERO_SESSION_TOKEN", "t")],
            Fake::new(KeyringRead::Missing),
        );
        assert_eq!(env.higher_precedence_source(), Some(Source::EnvToken));
        assert_eq!(
            chain(&[], Fake::new(KeyringRead::Missing)).higher_precedence_source(),
            None
        );
    }

    #[cfg(feature = "keyring")]
    #[test]
    fn would_use_names_the_step_a_reread_would_take() {
        let chain = chain(&OWN_DIR_ENV[..2], full_fake());
        assert_eq!(chain.would_use(), Some(Source::OwnKeyring));
    }

    /// The headless build has four steps: the keyring entries are never consulted.
    #[cfg(not(feature = "keyring"))]
    #[test]
    fn the_headless_order_is_token_explicit_file_own_file_eeroctl_file() {
        assert_eq!(
            resolved_name(&chain(&OWN_DIR_ENV, full_fake())),
            Some(("explicit file", "explicit".to_owned()))
        );
        assert_eq!(
            chain(&OWN_DIR_ENV[..2], full_fake()).would_use(),
            Some(Source::OwnFile)
        );
        let eeroctl = Fake::new(KeyringRead::record(record("shared-keyring")))
            .with_file(default_file(), FileRead::content(record("eeroctl")));
        assert_eq!(
            resolved_name(&chain(&OWN_DIR_ENV[..2], eeroctl)),
            Some(("eeroctl file", "eeroctl".to_owned()))
        );
    }

    #[test]
    fn the_explicit_file_is_the_own_file_when_both_paths_name_the_same_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let own_dir = dir.path().join("cfg");
        let own = own_dir.join("session.json");
        let env = |explicit: &Path| {
            EnvMap::from_pairs([
                (
                    "EERO_MCP_CONFIG_DIR",
                    own_dir.to_str().expect("utf-8").to_owned(),
                ),
                (
                    "EERO_MCP_SESSION_FILE",
                    explicit.to_str().expect("utf-8").to_owned(),
                ),
            ])
        };
        let check = |explicit: &Path| {
            let settings = Settings::from_env_for(&env(explicit), false).expect("valid");
            CredentialChain::new(&settings, Arc::new(SystemSources)).explicit_file_is_own_file()
        };
        // The directory does not exist yet, so the own file is compared through its parent as
        // written.
        assert!(check(&own));
        assert!(!check(&dir.path().join("elsewhere.json")));

        std::fs::create_dir_all(&own_dir).expect("mkdir");
        std::fs::write(&own, "{}").expect("write");
        assert!(check(&own));
        // A different spelling of the same path.
        assert!(check(&own_dir.join("..").join("cfg").join("session.json")));
        assert!(!check(&own_dir.join("other.json")));

        // Without an explicit file or without an own file there is nothing to compare.
        let none = Settings::from_env_for(&EnvMap::new(), false).expect("valid");
        assert!(!CredentialChain::new(&none, Arc::new(SystemSources)).explicit_file_is_own_file());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_the_own_file_counts_as_the_own_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let own_dir = dir.path().join("cfg");
        std::fs::create_dir_all(&own_dir).expect("mkdir");
        let own = own_dir.join("session.json");
        std::fs::write(&own, "{}").expect("write");
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&own, &link).expect("symlink");
        let settings = Settings::from_env_for(
            &EnvMap::from_pairs([
                (
                    "EERO_MCP_CONFIG_DIR",
                    own_dir.to_str().expect("utf-8").to_owned(),
                ),
                (
                    "EERO_MCP_SESSION_FILE",
                    link.to_str().expect("utf-8").to_owned(),
                ),
            ]),
            false,
        )
        .expect("valid");
        assert!(
            CredentialChain::new(&settings, Arc::new(SystemSources)).explicit_file_is_own_file()
        );
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
        fn keyring_record(&self, _: KeyringEntry) -> KeyringRead {
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
