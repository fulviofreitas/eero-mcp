//! The login module: the one place that signs in, signs out, and writes or deletes a credential.
//!
//! Everything here serves the login subcommand, the logout subcommand and the login tool. It is
//! the only module of the crate that may name rusteero's login flow, its credential-store types
//! with their save and clear operations, the transport builder that gives the login flow its base
//! URL, and the Client's sign-out call (the read-only guard in `tests/read_only_guard.rs` pins
//! each of these to this file, reached only through exact rusteero paths). It never loads from a
//! store, never writes a file itself, and never touches the shared keyring entry, eeroctl's file
//! or the explicit credential file: the stores it builds carry eero-mcp's own keyring names and
//! its own session file path only.
//!
//! # The login driver
//!
//! [`run_login`] drives one login: identifier, start (eero sends a one-time code by email or
//! SMS), code (an empty answer or `new` asks for a resend), verify. A code that eero rejects as
//! wrong or expired restarts the flow with a new start, so eero sends a new code. The limits are
//! [`MAX_IDENTIFIER_ENTRIES`] invalid identifier entries in a row, [`MAX_RESENDS`] resends and
//! [`MAX_ATTEMPTS`] verification attempts per run. The terminal and the chat differ only in their
//! [`Prompter`]. The driver returns the verified token and saves nothing: a front end decides
//! what to do with it ([`save_session`]), which lets the chat check for cancellation first.
//!
//! The identifier and the code are held as secrets and never logged, echoed or placed in an
//! error. Error classification branches on rusteero error variants, statuses and error codes
//! only, never on message text, and every text this module produces is fixed.
//!
//! # The own store
//!
//! [`OwnStore`] saves a session to eero-mcp's own keyring entry (with its own file as the
//! fallback) or to the own file alone, then reads it back through the same raw read the server
//! uses, reports which backend holds it, removes a leftover record of an earlier login from the
//! other backend, and checks that the own store now resolves to the new session.

use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(feature = "keyring")]
use rusteero::KeyringStore;
use rusteero::auth::flow::{LoginFlow, PendingLogin};
use rusteero::storage::{clear_async, save_async};
use rusteero::transport::Transport;
use rusteero::{ChainedStore, CredentialStore, Error, FileStore, Session, StorageError};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::Semaphore;

#[cfg(feature = "keyring")]
use crate::config::{OWN_KEYRING_ACCOUNT, OWN_KEYRING_SERVICE};
use crate::config::{Settings, api_base_url_allowed, token_shape_ok};
use crate::credentials::{CredentialChain, OwnRecord, Probe, Source};
use crate::server::production_client;

/// Invalid identifier entries in a row after which the login ends.
pub const MAX_IDENTIFIER_ENTRIES: u8 = 3;
/// Resends of the code per login run.
pub const MAX_RESENDS: u8 = 3;
/// Verification attempts per login run (each rejected code restarts the flow once).
pub const MAX_ATTEMPTS: u8 = 3;

/// The longest identifier accepted, in characters.
const MAX_IDENTIFIER_CHARS: usize = 254;
/// The longest code accepted, in characters.
const MAX_CODE_CHARS: usize = 32;

// ===================== the pure rules =====================

/// An identifier entry that breaks the rules. It never carries the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidIdentifier;

/// Applies the identifier rules: trimmed, 1 to 254 characters, no control characters. The result
/// is a secret: it is the email address or phone number of the account.
pub fn normalize_identifier(raw: &str) -> Result<SecretString, InvalidIdentifier> {
    let trimmed = raw.trim();
    let length = trimmed.chars().count();
    if length == 0 || length > MAX_IDENTIFIER_CHARS || trimmed.chars().any(char::is_control) {
        return Err(InvalidIdentifier);
    }
    Ok(SecretString::from(trimmed.to_owned()))
}

/// What a code entry asks for.
pub enum CodeEntry {
    /// An empty entry, or the word `new` in any letter case: send the code again.
    Resend,
    /// A well-formed code: 1 to 32 visible ASCII characters without spaces.
    Code(SecretString),
    /// Anything else: ask again without a request.
    Malformed,
}

/// Applies the code rules to an entry (trimmed first).
pub fn parse_code(raw: &str) -> CodeEntry {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("new") {
        return CodeEntry::Resend;
    }
    if trimmed.len() <= MAX_CODE_CHARS && trimmed.bytes().all(|byte| (0x21..=0x7E).contains(&byte))
    {
        CodeEntry::Code(SecretString::from(trimmed.to_owned()))
    } else {
        CodeEntry::Malformed
    }
}

// ===================== the prompter =====================

/// Why a code is being asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeKind {
    /// eero just sent the first code.
    First,
    /// The code was sent again at the user's request.
    Resent,
    /// The previous code was rejected, so eero sent a new one.
    New,
}

/// A recoverable problem the prompter should tell the user about before asking again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    /// The identifier entry broke the rules.
    InvalidIdentifier,
    /// The code entry was not 1 to 32 visible characters without spaces.
    MalformedCode,
    /// A resend was asked for after the resend limit was used up; nothing was sent.
    ResendLimit,
    /// eero did not resend the code.
    ResendFailed,
}

/// Why a prompter gave up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Abort {
    /// The input ended (the terminal's stdin was closed).
    InputEnded,
    /// The user declined or dismissed the form.
    Cancelled,
    /// The user did not answer in time.
    TimedOut,
    /// The client cannot show the form after all.
    CapabilityMissing,
    /// The client answered with nothing usable.
    Unusable,
}

/// How a front end asks the user. The terminal reads lines from stdin; the chat shows forms.
///
/// Answers are raw: the driver applies the identifier and code rules, so both front ends are held
/// to the same ones. Implementations must not log or echo what they are given.
pub trait Prompter: Send {
    /// Asks for the email address or phone number of the account.
    fn ask_identifier(&mut self) -> impl Future<Output = Result<SecretString, Abort>> + Send;

    /// Asks for the one-time code. An empty answer, or the word `new`, asks for a resend.
    fn ask_code(
        &mut self,
        kind: CodeKind,
    ) -> impl Future<Output = Result<SecretString, Abort>> + Send;

    /// Tells the user about a recoverable problem; the next question follows.
    fn report(&mut self, problem: Problem) -> impl Future<Output = ()> + Send;
}

// ===================== the driver =====================

/// Why a login ended without a session. Carries no identifier, code or message of eero's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginError {
    /// eero refused to start the login (an account that signs in with Amazon, a mistyped
    /// identifier, a blocked client).
    RefusedStart,
    /// The code was rejected as wrong or expired on every one of [`MAX_ATTEMPTS`] attempts.
    CodeRejected,
    /// eero refused the verification for another reason (a blocked account, too many attempts).
    VerificationRefused,
    /// [`MAX_IDENTIFIER_ENTRIES`] invalid identifier entries in a row.
    TooManyInvalidIdentifiers,
    /// eero rate-limited a login request.
    RateLimited {
        /// Whole seconds to wait, rounded up, when eero sent `Retry-After`.
        retry_after_seconds: Option<u64>,
    },
    /// eero could not be reached.
    Network,
    /// eero did not answer in time.
    Timeout,
    /// eero returned a token that cannot be used as a session.
    UnusableToken,
    /// Any other failure.
    Other,
    /// The prompter gave up.
    Aborted(Abort),
}

impl fmt::Display for LoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RefusedStart => "eero refused to start the login",
            Self::CodeRejected => "the code was not accepted",
            Self::VerificationRefused => "eero refused the verification",
            Self::TooManyInvalidIdentifiers => "no valid identifier was entered",
            Self::RateLimited { .. } => "eero rate-limited the login",
            Self::Network => "eero could not be reached",
            Self::Timeout => "eero did not answer in time",
            Self::UnusableToken => "eero returned a session that cannot be used",
            Self::Other => "the login failed",
            Self::Aborted(_) => "the login was not completed",
        })
    }
}

impl std::error::Error for LoginError {}

/// Builds the login flow on its own transport: no session, no store, default timeouts and
/// User-Agent, redirects refused. The base URL is applied only when it passes the same rule as
/// the Client builder's (https, or http on loopback), so a login never sends the identifier or
/// the code to an origin the configuration would not allow.
fn login_flow(api_base_url: Option<&str>) -> Result<LoginFlow, Error> {
    let mut builder = Transport::builder();
    if let Some(url) = api_base_url
        && api_base_url_allowed(url)
    {
        builder = builder.base_url(url);
    }
    Ok(LoginFlow::with_transport(builder.build()?))
}

/// Rate limits, network failures and timeouts end a login run; anything else is `Other`.
fn transport_failure(error: &Error) -> LoginError {
    match error {
        Error::RateLimit { retry_after, .. } => LoginError::RateLimited {
            retry_after_seconds: retry_after.map(|wait| {
                wait.as_secs()
                    .saturating_add(u64::from(wait.subsec_nanos() > 0))
            }),
        },
        Error::Network(_) => LoginError::Network,
        Error::Timeout => LoginError::Timeout,
        _ => LoginError::Other,
    }
}

/// How a failed verification ends or continues the run.
enum Verdict {
    /// A wrong or expired code, or a code eero refused the format of: start again.
    Rejected,
    /// The run ends.
    Fatal(LoginError),
}

/// Classifies a failed verification by variant, status and error code. A wrong code is a 401
/// without an error code, or `error.verification.invalid` / `.expired`; eero refusing the code's
/// format (a typo) counts too. The rest of the verification group (blocked, too many resends,
/// unknown or blocked login, unverified email) ends the run: a new start would send the user
/// another message.
fn classify_verification_failure(error: &Error) -> Verdict {
    match error {
        Error::Validation { .. } => Verdict::Rejected,
        Error::Authentication { .. } => match error.error_code() {
            Some("error.verification.invalid" | "error.verification.expired") => Verdict::Rejected,
            None if error.status() == Some(401) => Verdict::Rejected,
            _ => Verdict::Fatal(LoginError::VerificationRefused),
        },
        other => Verdict::Fatal(transport_failure(other)),
    }
}

/// Runs one request while holding one of the server's permits, when there is a semaphore.
async fn with_permit<T>(
    permits: Option<&Semaphore>,
    request: impl Future<Output = T>,
) -> Result<T, LoginError> {
    let _permit = match permits {
        Some(permits) => Some(permits.acquire().await.map_err(|_| LoginError::Other)?),
        None => None,
    };
    Ok(request.await)
}

/// Asks for the identifier until it passes the rules, at most [`MAX_IDENTIFIER_ENTRIES`] times.
async fn ask_identifier<P: Prompter>(prompter: &mut P) -> Result<SecretString, LoginError> {
    let mut invalid: u8 = 0;
    loop {
        let raw = prompter
            .ask_identifier()
            .await
            .map_err(LoginError::Aborted)?;
        if let Ok(identifier) = normalize_identifier(raw.expose_secret()) {
            return Ok(identifier);
        }
        invalid += 1;
        if invalid >= MAX_IDENTIFIER_ENTRIES {
            return Err(LoginError::TooManyInvalidIdentifiers);
        }
        prompter.report(Problem::InvalidIdentifier).await;
    }
}

/// Asks for the code until a well-formed one arrives, resending on request. `resends` counts
/// across restarts of the flow.
async fn ask_code<P: Prompter>(
    prompter: &mut P,
    pending: &PendingLogin,
    kind: &mut CodeKind,
    resends: &mut u8,
    permits: Option<&Semaphore>,
) -> Result<SecretString, LoginError> {
    loop {
        let raw = prompter
            .ask_code(*kind)
            .await
            .map_err(LoginError::Aborted)?;
        match parse_code(raw.expose_secret()) {
            CodeEntry::Code(code) => return Ok(code),
            CodeEntry::Malformed => prompter.report(Problem::MalformedCode).await,
            CodeEntry::Resend => {
                if *resends >= MAX_RESENDS {
                    prompter.report(Problem::ResendLimit).await;
                    continue;
                }
                *resends += 1;
                match with_permit(permits, pending.resend()).await? {
                    Ok(_) => *kind = CodeKind::Resent,
                    Err(error) => match transport_failure(&error) {
                        LoginError::Other => prompter.report(Problem::ResendFailed).await,
                        fatal => return Err(fatal),
                    },
                }
            }
        }
    }
}

/// Runs one login and returns the verified session token. Nothing is saved.
///
/// `identifier` is the one the caller already has (the login tool's argument); without it the
/// prompter is asked. `permits` is the server's semaphore: each start, resend and verify takes
/// one permit for its duration, and none is held while the prompter waits for the user.
/// `api_base_url` is `EERO_MCP_API_BASE_URL`, when set (it is applied only if it passes the
/// Client builder's rule).
///
/// Dropping the returned future abandons the run at its current await point: an in-flight wait or
/// request is dropped with the pending login, and nothing more is sent.
pub async fn run_login<P: Prompter>(
    api_base_url: Option<&str>,
    identifier: Option<SecretString>,
    prompter: &mut P,
    permits: Option<&Semaphore>,
) -> Result<SecretString, LoginError> {
    let flow = login_flow(api_base_url).map_err(|_| LoginError::Other)?;
    let identifier = match identifier {
        Some(identifier) => identifier,
        None => ask_identifier(prompter).await?,
    };
    let mut attempts: u8 = 0;
    let mut resends: u8 = 0;
    let mut kind = CodeKind::First;
    loop {
        let pending = with_permit(permits, flow.start(identifier.expose_secret()))
            .await?
            .map_err(|error| match error {
                Error::Authentication { .. } => LoginError::RefusedStart,
                other => transport_failure(&other),
            })?;
        let code = ask_code(prompter, &pending, &mut kind, &mut resends, permits).await?;
        match with_permit(permits, pending.verify(code.expose_secret())).await? {
            Ok(session) => {
                let token = session.token().clone();
                return if token_shape_ok(token.expose_secret()) {
                    Ok(token)
                } else {
                    Err(LoginError::UnusableToken)
                };
            }
            Err(error) => match classify_verification_failure(&error) {
                Verdict::Rejected => {
                    attempts += 1;
                    if attempts >= MAX_ATTEMPTS {
                        return Err(LoginError::CodeRejected);
                    }
                    kind = CodeKind::New;
                }
                Verdict::Fatal(fatal) => return Err(fatal),
            },
        }
    }
}

// ===================== the own store =====================

/// Where a session is held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreKind {
    /// eero-mcp's own OS keyring entry.
    Keyring,
    /// eero-mcp's own session file.
    File,
    /// Nowhere: the session lasts until the server stops (a chat login whose save failed).
    Memory,
}

impl StoreKind {
    /// The word the login result uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Keyring => "keyring",
            Self::File => "file",
            Self::Memory => "memory",
        }
    }
}

/// Why a session could not be saved. The storage error's own text is never shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveError {
    /// There is no backend at all: no keyring and no own directory (set `EERO_MCP_CONFIG_DIR`).
    NoLocation,
    /// A backend accepted the write and kept nothing.
    NotRetained,
    /// A backend (the keyring, say) reported a failure.
    Backend,
    /// An input-output failure writing the own file.
    Io,
    /// The save worked but another own record still resolves first.
    Shadowed,
    /// Anything else.
    Other,
}

impl SaveError {
    /// Fixed text for the user.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::NoLocation => {
                "there is nowhere to store the session: no keyring is available and no \
                 configuration directory could be found (set EERO_MCP_CONFIG_DIR)"
            }
            Self::NotRetained => "the credential store accepted the session but did not keep it",
            Self::Backend => "the credential store reported a failure",
            Self::Io => "the session file could not be written",
            Self::Shadowed => {
                "an older eero-mcp record would still take precedence over the new session"
            }
            Self::Other => "the session could not be saved",
        }
    }

    fn from_storage(error: &StorageError) -> Self {
        match error {
            StorageError::NotRetained { .. } => Self::NotRetained,
            StorageError::Backend { .. } => Self::Backend,
            StorageError::Io(_) => Self::Io,
            _ => Self::Other,
        }
    }
}

impl fmt::Display for SaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.describe())
    }
}

impl std::error::Error for SaveError {}

/// eero-mcp's own credential store: an optional keyring backend and an optional own file path.
///
/// Production builds it with [`OwnStore::production`]; tests inject a stand-in keyring backend
/// and a temporary path. The store only saves and clears (never loads): reads go through the
/// credential chain's raw read.
pub struct OwnStore {
    keyring: Option<Arc<dyn CredentialStore>>,
    file: Option<PathBuf>,
}

impl fmt::Debug for OwnStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnStore")
            .field("keyring", &self.keyring.is_some())
            .field("file", &self.file.is_some())
            .finish()
    }
}

impl OwnStore {
    /// A store over the given backends.
    pub fn new(keyring: Option<Arc<dyn CredentialStore>>, file: Option<PathBuf>) -> Self {
        Self { keyring, file }
    }

    /// The production store for `settings`: eero-mcp's own keyring entry (keyring builds, unless
    /// `EERO_MCP_NO_KEYRING` is 1) and its own session file.
    pub fn production(settings: &Settings) -> Self {
        #[cfg(feature = "keyring")]
        let keyring: Option<Arc<dyn CredentialStore>> = settings.keyring_enabled.then(|| {
            Arc::new(
                KeyringStore::with_entry(OWN_KEYRING_SERVICE, OWN_KEYRING_ACCOUNT)
                    .warn_on_unpersisted(false),
            ) as Arc<dyn CredentialStore>
        });
        #[cfg(not(feature = "keyring"))]
        let keyring: Option<Arc<dyn CredentialStore>> = None;
        Self::new(keyring, settings.own_file.clone())
    }

    /// Whether there is anywhere to save a session.
    pub fn has_backend(&self) -> bool {
        self.keyring.is_some() || self.file.is_some()
    }

    /// The own session file's path, when there is one.
    pub fn file_path(&self) -> Option<&Path> {
        self.file.as_deref()
    }

    /// The store a save goes through: the keyring first with the own file as the fallback, or
    /// either alone.
    fn backend(&self) -> Option<Arc<dyn CredentialStore>> {
        match (&self.keyring, &self.file) {
            (Some(keyring), Some(path)) => Some(Arc::new(ChainedStore::new(
                Arc::clone(keyring),
                Arc::new(FileStore::new(path.clone())),
            ))),
            (Some(keyring), None) => Some(Arc::clone(keyring)),
            (None, Some(path)) => Some(Arc::new(FileStore::new(path.clone()))),
            (None, None) => None,
        }
    }

    /// Deletes both backends' records, each attempted whatever the other's outcome.
    pub async fn clear_all(&self) -> ClearOutcome {
        let keyring = match &self.keyring {
            Some(keyring) => Some(clear_async(Arc::clone(keyring)).await.is_ok()),
            None => None,
        };
        let file = match &self.file {
            Some(path) => Some(
                clear_async(Arc::new(FileStore::new(path.clone())))
                    .await
                    .is_ok(),
            ),
            None => None,
        };
        ClearOutcome { keyring, file }
    }

    /// Deletes the own file's record only (the leftover of an earlier login).
    async fn clear_file(&self) -> bool {
        match &self.file {
            Some(path) => clear_async(Arc::new(FileStore::new(path.clone())))
                .await
                .is_ok(),
            None => false,
        }
    }

    /// Deletes the own keyring entry only (the leftover of an earlier login).
    async fn clear_keyring(&self) -> bool {
        match &self.keyring {
            Some(keyring) => clear_async(Arc::clone(keyring)).await.is_ok(),
            None => false,
        }
    }
}

/// What deleting the two own backends came to. `None`: there is no such backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClearOutcome {
    /// The keyring entry was deleted (`Some(true)`), could not be (`Some(false)`), or does not
    /// apply (`None`).
    pub keyring: Option<bool>,
    /// The same for the own file.
    pub file: Option<bool>,
}

/// Runs a blocking read of the credential chain on tokio's blocking pool.
async fn read_chain<T: Send + 'static>(
    chain: &Arc<CredentialChain>,
    read: impl FnOnce(&CredentialChain) -> T + Send + 'static,
) -> Option<T> {
    let chain = Arc::clone(chain);
    tokio::task::spawn_blocking(move || read(&chain)).await.ok()
}

/// Whether `held` is the token `expected`.
fn holds(held: Option<&SecretString>, expected: &SecretString) -> bool {
    held.is_some_and(|held| held.expose_secret() == expected.expose_secret())
}

/// Saves a verified session to the own store and proves it landed.
///
/// 1. Saves through rusteero's verified stores on tokio's blocking pool (the keyring first with
///    the own file as the fallback; either alone when only one exists).
/// 2. Reads the own store back through the credential chain's raw read: the backend whose record
///    equals the new token is the store reported.
/// 3. Removes a leftover record of an earlier login from the other backend (best effort):
///    rusteero's chained store retires only records it wrote itself, and a fresh instance has
///    written none.
/// 4. Checks that the own store now resolves to the new token.
pub async fn save_session(
    store: &OwnStore,
    chain: &Arc<CredentialChain>,
    token: &SecretString,
) -> Result<StoreKind, SaveError> {
    let backend = store.backend().ok_or(SaveError::NoLocation)?;
    let session = Session::from_token(token.expose_secret());
    save_async(backend, session)
        .await
        .map_err(|error| SaveError::from_storage(&error))?;

    let records = read_chain(chain, CredentialChain::own_records)
        .await
        .ok_or(SaveError::Other)?;
    let kind = if holds(records.keyring.token(), token) {
        StoreKind::Keyring
    } else if holds(records.file.token(), token) {
        StoreKind::File
    } else {
        return Err(SaveError::NotRetained);
    };

    // A different token in the other backend is a leftover that could shadow the new login.
    let leftover = |record: &OwnRecord| record.token().is_some() && !holds(record.token(), token);
    match kind {
        StoreKind::Keyring if leftover(&records.file) => {
            store.clear_file().await;
        }
        StoreKind::File if leftover(&records.keyring) => {
            store.clear_keyring().await;
        }
        _ => {}
    }

    let resolved = read_chain(chain, CredentialChain::own_store_token)
        .await
        .ok_or(SaveError::Other)?;
    if holds(resolved.as_ref(), token) {
        Ok(kind)
    } else {
        Err(SaveError::Shadowed)
    }
}

// ===================== sign-out =====================

/// Asks eero to end the session `token` (best effort): one sign-out request through a Client that
/// holds only that session and no store. rusteero ignores eero's answer and every failure of the
/// request, so the result says only whether the request was sent (`false`: the Client could not
/// be built).
pub async fn revoke_session(api_base_url: Option<&str>, token: &SecretString) -> bool {
    match production_client(api_base_url, Some(token)).await {
        Ok(client) => client.logout().await.is_ok(),
        Err(_) => false,
    }
}

/// A store or source whose contents could not be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotChecked {
    /// The system keyring (eero-mcp's entry): disabled, not compiled in or unreachable. An
    /// earlier eero-mcp keyring record may survive there.
    Keyring,
    /// Another credential source whose copy of a token could not be ruled out.
    Source(Source),
}

/// A session whose sign-out was skipped because another credential source holds the same token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldElsewhere {
    /// The own backends that held the session; they are deleted locally all the same.
    pub stores: Vec<StoreKind>,
    /// The other sources that hold the same token.
    pub sources: Vec<Source>,
}

/// What a logout did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogoutReport {
    /// The own backends in which a record was found.
    pub found: Vec<StoreKind>,
    /// One entry per sign-out request sent: the own backends that held that session.
    pub revoked: Vec<Vec<StoreKind>>,
    /// Sessions deleted locally without a sign-out request, because another source holds them.
    pub held_elsewhere: Vec<HeldElsewhere>,
    /// Sign-out requests that could not be sent at all (the Client could not be built).
    pub revoke_not_sent: usize,
    /// The own backends whose record was found and deleted.
    pub removed: Vec<StoreKind>,
    /// The own backends whose record was found and could not be deleted.
    pub delete_failed: Vec<StoreKind>,
    /// What could not be checked.
    pub not_checked: Vec<NotChecked>,
    /// The step the credential chain would use now, by name, without checking it with eero.
    pub next_source: Option<Source>,
}

impl LogoutReport {
    /// Whether every own backend that was checked ended empty.
    pub fn ok(&self) -> bool {
        self.delete_failed.is_empty()
    }
}

/// Signs out and deletes eero-mcp's own session.
///
/// 1. Reads the own store through the credential chain's raw read.
/// 2. For each distinct session found, reads the other sources (environment token, explicit file,
///    shared keyring entry, eeroctl's file): when one holds the same token the sign-out is
///    skipped, because it would end that login too; otherwise one sign-out request is sent
///    through a Client that holds only that session.
/// 3. Deletes the own keyring entry and the own file, each attempted whatever the other's outcome.
///
/// The caller has already refused to run when the explicit file is the own file. The shared
/// stores, the environment token and the explicit file are never touched.
pub async fn sign_out_own_session(
    api_base_url: Option<&str>,
    store: &OwnStore,
    chain: &Arc<CredentialChain>,
) -> LogoutReport {
    let mut report = LogoutReport::default();

    let records = read_chain(chain, CredentialChain::own_records).await;
    let (keyring, file) = records.map_or((OwnRecord::Absent, OwnRecord::Absent), |records| {
        (records.keyring, records.file)
    });
    if matches!(keyring, OwnRecord::NotChecked) {
        report.not_checked.push(NotChecked::Keyring);
    }
    if keyring.exists() {
        report.found.push(StoreKind::Keyring);
    }
    if file.exists() {
        report.found.push(StoreKind::File);
    }

    // The distinct usable tokens, each with the backends that hold it.
    let mut sessions: Vec<(SecretString, Vec<StoreKind>)> = Vec::new();
    for (kind, record) in [(StoreKind::Keyring, &keyring), (StoreKind::File, &file)] {
        let Some(token) = record.token() else {
            continue;
        };
        match sessions
            .iter_mut()
            .find(|(known, _)| known.expose_secret() == token.expose_secret())
        {
            Some((_, holders)) => holders.push(kind),
            None => sessions.push((token.clone(), vec![kind])),
        }
    }

    if !sessions.is_empty() {
        let mut others: Vec<(Source, SecretString)> = Vec::new();
        for source in [
            Source::EnvToken,
            Source::ExplicitFile,
            Source::SharedKeyring,
            Source::EeroctlFile,
        ] {
            match read_chain(chain, move |chain| chain.probe(source)).await {
                Some(Probe::Token(token)) => others.push((source, token)),
                Some(Probe::Empty) => {}
                Some(Probe::NotChecked) | None => {
                    report.not_checked.push(NotChecked::Source(source));
                }
            }
        }
        for (token, stores) in sessions {
            let sources: Vec<Source> = others
                .iter()
                .filter(|(_, other)| holds(Some(other), &token))
                .map(|(source, _)| *source)
                .collect();
            if !sources.is_empty() {
                report
                    .held_elsewhere
                    .push(HeldElsewhere { stores, sources });
            } else if revoke_session(api_base_url, &token).await {
                report.revoked.push(stores);
            } else {
                report.revoke_not_sent += 1;
            }
        }
    }

    let cleared = store.clear_all().await;
    for (kind, outcome) in [
        (StoreKind::Keyring, cleared.keyring),
        (StoreKind::File, cleared.file),
    ] {
        if !report.found.contains(&kind) {
            continue;
        }
        match outcome {
            Some(true) => report.removed.push(kind),
            _ => report.delete_failed.push(kind),
        }
    }

    report.next_source = read_chain(chain, CredentialChain::would_use)
        .await
        .flatten();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_trimmed_and_bounded() {
        let ok = |raw: &str| {
            normalize_identifier(raw)
                .map(|identifier| identifier.expose_secret().to_owned())
                .ok()
        };
        assert_eq!(
            ok("  user@example.com \n").as_deref(),
            Some("user@example.com")
        );
        assert_eq!(ok("+15555550100").as_deref(), Some("+15555550100"));
        assert_eq!(ok("a").as_deref(), Some("a"));
        let longest = "a".repeat(254);
        assert_eq!(ok(&longest).as_deref(), Some(longest.as_str()));
        // Characters, not bytes.
        let wide = "\u{e9}".repeat(254);
        assert_eq!(ok(&wide).as_deref(), Some(wide.as_str()));
        for bad in [
            "",
            "   ",
            "\t\n",
            &"a".repeat(255),
            "user@exa\nmple.com",
            "a\u{0}b",
            "a\u{7f}b",
        ] {
            assert!(ok(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn codes_resend_on_empty_or_new_and_otherwise_must_be_short_visible_ascii() {
        assert!(matches!(parse_code(""), CodeEntry::Resend));
        assert!(matches!(parse_code("  \n"), CodeEntry::Resend));
        for new in ["new", "NEW", "New", " nEw "] {
            assert!(matches!(parse_code(new), CodeEntry::Resend), "{new:?}");
        }
        let code = |raw: &str| match parse_code(raw) {
            CodeEntry::Code(code) => Some(code.expose_secret().to_owned()),
            _ => None,
        };
        assert_eq!(code(" 000001 \n").as_deref(), Some("000001"));
        assert_eq!(code("ab-12_CD~!").as_deref(), Some("ab-12_CD~!"));
        // Only the exact word new asks for a resend.
        assert_eq!(code("newer").as_deref(), Some("newer"));
        let longest = "9".repeat(32);
        assert_eq!(code(&longest).as_deref(), Some(longest.as_str()));
        for bad in [
            "0000 01",
            "00\t01",
            &"9".repeat(33),
            "c\u{f3}digo",
            "\u{0}1",
            "new code",
        ] {
            assert!(
                matches!(parse_code(bad), CodeEntry::Malformed),
                "{bad:?} is malformed"
            );
        }
    }

    #[test]
    fn the_limits_are_three() {
        assert_eq!(MAX_IDENTIFIER_ENTRIES, 3);
        assert_eq!(MAX_RESENDS, 3);
        assert_eq!(MAX_ATTEMPTS, 3);
    }

    #[test]
    fn store_kinds_have_the_documented_words() {
        assert_eq!(StoreKind::Keyring.as_str(), "keyring");
        assert_eq!(StoreKind::File.as_str(), "file");
        assert_eq!(StoreKind::Memory.as_str(), "memory");
    }
}
