//! The login, logout and status subcommands of the `eero-mcp` binary.
//!
//! They read the same configuration as the server (a configuration error ends them with exit
//! status 1 and the server's message), honour `EERO_MCP_API_BASE_URL`, and never serve MCP. They
//! take no arguments of their own: the identifier and the code are read from stdin, one line at a
//! time, never from the command line, so they stay out of shell history and process listings.
//!
//! Results go to stdout; prompts, failures and logs go to stderr. Nothing here prints the token,
//! the identifier or the code. The own session file's path is shown only by the login and logout
//! results, on the user's own terminal; the status subcommand prints source names only.
//!
//! All the work is in [`crate::auth`]; this module is the terminal front end: a [`Prompter`] that
//! reads stdin, and the reports and exit statuses.

use std::fmt;
use std::io::{BufRead, Write};
use std::sync::Arc;

use rusteero::Error;
use secrecy::SecretString;

use crate::auth::{
    Abort, CodeKind, LoginError, LogoutReport, NotChecked, OwnStore, Problem, Prompter,
    ReplacedOutcome, StartBudget, StoreKind, revoke_replaced, revoke_session, run_login,
    save_session, sign_out_own_session,
};
use crate::config::{EnvMap, Settings};
use crate::credentials::{CredentialChain, Source, resolve_at_startup_resolved};
use crate::server::production_client;

/// A line over this many bytes is invalid input.
pub const MAX_LINE_BYTES: usize = 1024;

/// The subcommands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Sign in with a one-time code and save the session to eero-mcp's own store.
    Login,
    /// Sign out eero-mcp's own session and delete it.
    Logout,
    /// Show which credential the server would use, and whether eero accepts it.
    Status,
}

impl Command {
    /// The subcommand a word names.
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "login" => Some(Self::Login),
            "logout" => Some(Self::Logout),
            "status" => Some(Self::Status),
            _ => None,
        }
    }
}

/// What reading one line of input came to.
///
/// A text line is what the user typed at a prompt: an identifier or a one-time code. Its `Debug`
/// output is written by hand and shows the length only, so no `{:?}` or `?line` in a log line, a
/// panic message or a failed assertion can print it.
#[derive(Clone, PartialEq, Eq)]
pub enum Line {
    /// A line (without its line ending).
    Text(String),
    /// A line that is not valid UTF-8 or longer than [`MAX_LINE_BYTES`].
    Invalid,
    /// The input ended.
    End,
}

impl fmt::Debug for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => write!(f, "Text(<redacted, {} bytes>)", text.len()),
            Self::Invalid => f.write_str("Invalid"),
            Self::End => f.write_str("End"),
        }
    }
}

/// Reads one line from `reader`, holding at most `max` bytes of it: a longer line is read to its
/// end (so the next call starts on the next line) and reported as [`Line::Invalid`].
pub fn read_line_bounded<R: BufRead>(reader: &mut R, max: usize) -> Line {
    let mut line: Vec<u8> = Vec::new();
    let mut too_long = false;
    let mut saw_any = false;
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        if available.is_empty() {
            break;
        }
        saw_any = true;
        let (chunk, found_end) = match available.iter().position(|byte| *byte == b'\n') {
            Some(position) => (&available[..position], true),
            None => (available, false),
        };
        if !too_long {
            if line.len() + chunk.len() > max {
                too_long = true;
                line.clear();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let consumed = chunk.len() + usize::from(found_end);
        reader.consume(consumed);
        if found_end {
            break;
        }
    }
    if !saw_any {
        return Line::End;
    }
    if too_long {
        return Line::Invalid;
    }
    String::from_utf8(line).map_or(Line::Invalid, |text| {
        Line::Text(text.trim_end_matches('\r').to_owned())
    })
}

/// A source of input lines.
pub trait LineSource: Send {
    /// The next line.
    fn next_line(&mut self) -> Line;
}

/// Lines from the process's stdin.
#[derive(Debug, Default)]
pub struct StdinLines;

impl LineSource for StdinLines {
    fn next_line(&mut self) -> Line {
        read_line_bounded(&mut std::io::stdin().lock(), MAX_LINE_BYTES)
    }
}

/// Prints a prompt on stderr and leaves the cursor on its line.
fn prompt(text: &str) {
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{text}");
    let _ = stderr.flush();
}

/// The terminal [`Prompter`]: prompts on stderr, answers from a line source. Nothing the user
/// types is echoed back.
pub struct TerminalPrompter<S: LineSource> {
    source: S,
}

impl<S: LineSource> TerminalPrompter<S> {
    /// A prompter reading from `source`.
    pub fn new(source: S) -> Self {
        Self { source }
    }
}

// The reads are blocking by design: the subcommand does nothing else while it waits for the user.
#[allow(clippy::unused_async_trait_impl)]
impl<S: LineSource> Prompter for TerminalPrompter<S> {
    async fn ask_identifier(&mut self) -> Result<SecretString, Abort> {
        prompt("Email address or phone number of your eero account: ");
        match self.source.next_line() {
            Line::Text(text) => Ok(SecretString::from(text)),
            // Fails the identifier rules, so the driver reports it and asks again.
            Line::Invalid => Ok(SecretString::from(String::new())),
            Line::End => Err(Abort::InputEnded),
        }
    }

    async fn ask_code(&mut self, kind: CodeKind) -> Result<SecretString, Abort> {
        prompt(match kind {
            CodeKind::First => {
                "eero sent a one-time code by email or SMS. Enter it (an empty line or new sends it again): "
            }
            CodeKind::Resent => {
                "eero sent the code again. Enter it (an empty line or new sends it again): "
            }
            CodeKind::New => {
                "That code was not accepted, so eero sent a new one. Enter the new code (an empty line or new sends it again): "
            }
        });
        match self.source.next_line() {
            Line::Text(text) => Ok(SecretString::from(text)),
            // Fails the code rules (it holds a space), so the driver reports it and asks again.
            Line::Invalid => Ok(SecretString::from("invalid input".to_owned())),
            Line::End => Err(Abort::InputEnded),
        }
    }

    async fn report(&mut self, problem: Problem) {
        eprintln!(
            "{}",
            match problem {
                Problem::InvalidIdentifier => {
                    "That does not look like an email address or phone number."
                }
                Problem::MalformedCode => {
                    "That does not look like a code: it is 1 to 32 characters without spaces."
                }
                Problem::ResendLimit => "The code cannot be sent again in this login.",
                Problem::ResendFailed => "eero could not send the code again.",
            }
        );
    }
}

/// Fixed text for a login that ended without a session.
fn login_failure_text(error: &LoginError) -> String {
    match error {
        LoginError::RefusedStart => "eero refused to start the login. Check the email address or phone number. Accounts that sign in with Amazon cannot use code login; a standard eero account (email or phone) invited as an admin of the network can.".to_owned(),
        LoginError::CodeRejected => "eero did not accept the code after 3 attempts.".to_owned(),
        LoginError::VerificationRefused => "eero refused the verification (for example a blocked account or too many attempts).".to_owned(),
        LoginError::TooManyInvalidIdentifiers => {
            "No valid email address or phone number was entered.".to_owned()
        }
        LoginError::RateLimited { retry_after_seconds: Some(seconds) } => {
            format!("eero rate-limited the login. Wait {seconds} seconds and try again.")
        }
        LoginError::RateLimited { retry_after_seconds: None } => {
            "eero rate-limited the login. Wait a while and try again.".to_owned()
        }
        LoginError::StartBudgetExhausted { retry_after_seconds } => format!(
            "This run has used up its login starts (3 in 15 minutes), so no further code was requested. Nothing was sent. Wait {retry_after_seconds} seconds and try again."
        ),
        LoginError::Network => {
            "Could not reach the eero cloud API. Check the connection and try again.".to_owned()
        }
        LoginError::Timeout => "The eero cloud API did not answer in time. Try again.".to_owned(),
        LoginError::UnusableToken => "eero returned a session this program cannot use.".to_owned(),
        LoginError::Aborted(Abort::InputEnded) => {
            "The input ended before the login was complete.".to_owned()
        }
        LoginError::Other | LoginError::Aborted(_) => "The login failed.".to_owned(),
    }
}

const EXPLICIT_IS_OWN: &str = "EERO_MCP_SESSION_FILE names eero-mcp's own session file, so this would overwrite or delete a configured credential. Unset EERO_MCP_SESSION_FILE (the own store is read anyway) and run the command again. Nothing was sent to eero.";

/// Whether the explicit file is the own file, computed on the blocking pool.
async fn explicit_is_own(chain: &Arc<CredentialChain>) -> bool {
    let chain = Arc::clone(chain);
    tokio::task::spawn_blocking(move || chain.explicit_file_is_own_file())
        .await
        .unwrap_or(false)
}

/// Runs a subcommand and returns its exit status (0 on success, 1 on any failure).
pub async fn run(command: Command, env: &EnvMap) -> u8 {
    let settings = match Settings::from_env(env) {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("eero-mcp: {error}");
            return 1;
        }
    };
    let chain = Arc::new(CredentialChain::from_settings(&settings));
    match command {
        Command::Login => run_login_command(&settings, &chain, StdinLines).await,
        Command::Logout => run_logout_command(&settings, &chain).await,
        Command::Status => run_status_command(&settings, &chain).await,
    }
}

/// The login subcommand over any line source.
pub async fn run_login_command<S: LineSource>(
    settings: &Settings,
    chain: &Arc<CredentialChain>,
    source: S,
) -> u8 {
    let store = OwnStore::production(settings);
    if explicit_is_own(chain).await {
        eprintln!("eero-mcp: {EXPLICIT_IS_OWN}");
        return 1;
    }
    // Refuse before eero sends the user a code that could not be kept.
    if !store.has_backend() {
        eprintln!(
            "eero-mcp: {} Nothing was sent to eero.",
            crate::auth::SaveError::NoLocation.describe()
        );
        return 1;
    }

    let mut prompter = TerminalPrompter::new(source);
    // One run is one process: the budget bounds the starts of this run (at most three by the
    // attempt limit) and exists so that no caller of the driver can skip it.
    let budget = StartBudget::standard();
    let token = match run_login(
        settings.api_base_url.as_deref(),
        None,
        &mut prompter,
        None,
        &budget,
    )
    .await
    {
        Ok(token) => token,
        Err(error) => {
            eprintln!("eero-mcp: {}", login_failure_text(&error));
            return 1;
        }
    };

    match save_session(&store, chain, &token).await {
        Ok(saved) => {
            match saved.kind {
                StoreKind::File => match store.file_path() {
                    Some(path) => {
                        println!("Logged in. The session is stored in {}.", path.display());
                    }
                    None => println!("Logged in. The session is stored in the own session file."),
                },
                StoreKind::Keyring | StoreKind::Memory => {
                    println!(
                        "Logged in. The session is stored in the system keyring (the eero-mcp entry)."
                    );
                }
            }
            let for_check = Arc::clone(chain);
            let higher = tokio::task::spawn_blocking(move || for_check.higher_precedence_source())
                .await
                .ok()
                .flatten();
            match higher {
                Some(Source::EnvToken) => println!(
                    "Note: RUSTEERO_SESSION_TOKEN is set and takes precedence over this login."
                ),
                Some(Source::ExplicitFile) => println!(
                    "Note: EERO_MCP_SESSION_FILE holds a usable token and takes precedence over this login."
                ),
                _ => println!("A running eero-mcp server picks this session up without a restart."),
            }
            // Logging in again must end the session it replaced, not leave it live in no store.
            if saved.replaced_count() > 0 {
                let outcome = revoke_replaced(settings.api_base_url.as_deref(), chain, saved).await;
                print_replaced_outcome(&outcome);
            }
            0
        }
        Err(error) => {
            eprintln!(
                "eero-mcp: the session could not be saved: {}.",
                error.describe()
            );
            // No session that nothing stores may stay live.
            if revoke_session(settings.api_base_url.as_deref(), &token).await {
                eprintln!("The new session was signed out at eero (a sign-out request was sent).");
            } else {
                eprintln!("The new session could not be signed out at eero.");
            }
            1
        }
    }
}

/// What signing out the replaced session came to, on stdout.
fn print_replaced_outcome(outcome: &ReplacedOutcome) {
    if outcome.revoked > 0 {
        println!(
            "The previous eero-mcp session was signed out: a sign-out request was sent to eero (its answer is not reported)."
        );
    }
    if outcome.held_elsewhere > 0 {
        println!(
            "The previous eero-mcp session was not signed out at eero, because another credential source also holds it."
        );
    }
    if outcome.not_sent > 0 {
        println!("A sign-out request for the previous eero-mcp session could not be sent.");
    }
}

/// The names of own backends, for the reports.
fn stores_text(stores: &[StoreKind], settings_file: Option<&std::path::Path>) -> String {
    stores
        .iter()
        .map(|store| match (store, settings_file) {
            (StoreKind::File, Some(path)) => path.display().to_string(),
            (StoreKind::File, None) => "the own session file".to_owned(),
            _ => "the system keyring (the eero-mcp entry)".to_owned(),
        })
        .collect::<Vec<_>>()
        .join(" and ")
}

/// The logout subcommand: sign out and delete eero-mcp's own session.
pub async fn run_logout_command(settings: &Settings, chain: &Arc<CredentialChain>) -> u8 {
    if explicit_is_own(chain).await {
        eprintln!("eero-mcp: {EXPLICIT_IS_OWN}");
        return 1;
    }
    let store = OwnStore::production(settings);
    let report = sign_out_own_session(settings.api_base_url.as_deref(), &store, chain).await;
    print_logout_report(&report, store.file_path());
    u8::from(!report.ok())
}

fn print_logout_report(report: &LogoutReport, file: Option<&std::path::Path>) {
    if report.found.is_empty() {
        println!("No eero-mcp session was stored.");
    }
    for stores in &report.revoked {
        println!(
            "Signed out the session held in {}: a sign-out request was sent to eero (its answer is not reported).",
            stores_text(stores, file)
        );
    }
    for held in &report.held_elsewhere {
        let sources = held
            .sources
            .iter()
            .map(|source| source.name())
            .collect::<Vec<_>>()
            .join(" and ");
        println!(
            "The session held in {} was deleted locally without signing out at eero, because the {sources} also holds it.",
            stores_text(&held.stores, file)
        );
    }
    if report.revoke_not_sent > 0 {
        println!("A sign-out request could not be sent; the local copy was deleted all the same.");
    }
    if !report.removed.is_empty() {
        println!("Removed: {}.", stores_text(&report.removed, file));
    }
    if !report.delete_failed.is_empty() {
        eprintln!(
            "eero-mcp: could not delete: {}.",
            stores_text(&report.delete_failed, file)
        );
    }
    for unchecked in &report.not_checked {
        match unchecked {
            NotChecked::Keyring => println!(
                "Not checked: the system keyring (the eero-mcp entry) is disabled or unreachable; an earlier eero-mcp record may survive there."
            ),
            NotChecked::Source(source) => println!(
                "Not checked: the {} could not be read, so a copy of the session there cannot be ruled out.",
                source.name()
            ),
        }
    }
    match report.next_source {
        Some(source) => println!("The server would now use: {}.", source.name()),
        None => println!("No credential source remains."),
    }
}

/// The status subcommand: which credential the server would use, and whether eero accepts it.
pub async fn run_status_command(settings: &Settings, chain: &Arc<CredentialChain>) -> u8 {
    let resolved = match resolve_at_startup_resolved(Arc::clone(chain)).await {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("eero-mcp: {error}");
            return 1;
        }
    };
    let Some(resolved) = resolved else {
        println!("credential source: none");
        println!(
            "No eero credential was found. Run the login subcommand of eero-mcp in a terminal to sign in."
        );
        return 1;
    };
    println!("credential source: {}", resolved.source.name());

    let Ok(client) =
        production_client(settings.api_base_url.as_deref(), Some(&resolved.token)).await
    else {
        println!("session: unreachable (the eero client could not be built)");
        return 1;
    };
    match client.get_account(true).await {
        Ok(_) => {
            println!("session: valid");
            0
        }
        Err(Error::Authentication { .. }) => {
            println!("session: rejected (log in again)");
            1
        }
        Err(Error::RateLimit { .. }) => {
            println!("session: unreachable (rate limited)");
            1
        }
        Err(Error::Network(_)) => {
            println!("session: unreachable (network failure)");
            1
        }
        Err(Error::Timeout) => {
            println!("session: unreachable (timeout)");
            1
        }
        Err(_) => {
            println!("session: unreachable (eero error)");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use secrecy::ExposeSecret;

    use super::*;

    fn lines(input: &[u8], max: usize) -> Vec<Line> {
        let mut reader = Cursor::new(input.to_vec());
        let mut out = Vec::new();
        loop {
            let line = read_line_bounded(&mut reader, max);
            let end = line == Line::End;
            out.push(line);
            if end {
                return out;
            }
        }
    }

    #[test]
    fn lines_are_split_on_newlines_and_carriage_returns_are_dropped() {
        assert_eq!(
            lines(b"one\ntwo\r\n\nlast", 64),
            vec![
                Line::Text("one".to_owned()),
                Line::Text("two".to_owned()),
                Line::Text(String::new()),
                Line::Text("last".to_owned()),
                Line::End
            ]
        );
        assert_eq!(lines(b"", 64), vec![Line::End]);
        assert_eq!(lines(b"\n", 64), vec![Line::Text(String::new()), Line::End]);
    }

    #[test]
    fn a_line_over_the_limit_is_invalid_and_does_not_swallow_the_next_one() {
        let long = "x".repeat(40);
        let input = format!("{long}\nshort\n{long}");
        assert_eq!(
            lines(input.as_bytes(), 32),
            vec![
                Line::Invalid,
                Line::Text("short".to_owned()),
                Line::Invalid,
                Line::End
            ]
        );
        // Exactly at the limit is fine.
        let exact = "y".repeat(32);
        assert_eq!(
            lines(exact.as_bytes(), 32),
            vec![Line::Text(exact.clone()), Line::End]
        );
    }

    #[test]
    fn a_line_that_is_not_utf8_is_invalid() {
        assert_eq!(
            lines(b"\xff\xfe\nok\n", 64),
            vec![Line::Invalid, Line::Text("ok".to_owned()), Line::End]
        );
    }

    #[test]
    fn a_long_line_is_bounded_in_memory_across_buffer_refills() {
        // A reader with a tiny buffer sees the line in many chunks.
        let input = format!("{}\nok\n", "z".repeat(10_000));
        let mut reader = std::io::BufReader::with_capacity(16, Cursor::new(input.into_bytes()));
        assert_eq!(
            read_line_bounded(&mut reader, MAX_LINE_BYTES),
            Line::Invalid
        );
        assert_eq!(
            read_line_bounded(&mut reader, MAX_LINE_BYTES),
            Line::Text("ok".to_owned())
        );
    }

    #[test]
    fn a_text_line_never_prints_what_the_user_typed() {
        let line = Line::Text("123456".to_owned());
        for shown in [format!("{line:?}"), format!("{line:#?}")] {
            assert!(!shown.contains("123456"), "{shown}");
            assert!(shown.contains("redacted"), "{shown}");
        }
        assert_eq!(
            format!("{:?}", Line::Text("user@example.com".to_owned())),
            "Text(<redacted, 16 bytes>)"
        );
        // Collections, assertions and logs print through Debug too.
        let many = format!(
            "{:?}",
            vec![
                Line::Text("user@example.com".to_owned()),
                Line::Invalid,
                Line::End
            ]
        );
        assert!(!many.contains("example.com"), "{many}");
        assert_eq!(
            format!("{:?} {:?}", Line::Invalid, Line::End),
            "Invalid End"
        );
    }

    #[test]
    fn subcommand_words_parse_exactly() {
        assert_eq!(Command::parse("login"), Some(Command::Login));
        assert_eq!(Command::parse("logout"), Some(Command::Logout));
        assert_eq!(Command::parse("status"), Some(Command::Status));
        for other in ["", "Login", "LOGIN", "serve", "--help", "login ", "log-in"] {
            assert_eq!(Command::parse(other), None, "{other:?}");
        }
    }

    struct Scripted(Vec<Line>);

    impl LineSource for Scripted {
        fn next_line(&mut self) -> Line {
            if self.0.is_empty() {
                Line::End
            } else {
                self.0.remove(0)
            }
        }
    }

    #[tokio::test]
    async fn the_terminal_prompter_turns_invalid_input_into_entries_the_rules_reject() {
        let mut prompter = TerminalPrompter::new(Scripted(vec![
            Line::Invalid,
            Line::Invalid,
            Line::Text("answer".to_owned()),
            Line::End,
        ]));
        let identifier = prompter.ask_identifier().await.expect("an entry");
        assert!(crate::auth::normalize_identifier(identifier.expose_secret()).is_err());
        let code = prompter.ask_code(CodeKind::First).await.expect("an entry");
        assert!(matches!(
            crate::auth::parse_code(code.expose_secret()),
            crate::auth::CodeEntry::Malformed
        ));
        let code = prompter.ask_code(CodeKind::New).await.expect("an entry");
        assert_eq!(code.expose_secret(), "answer");
        assert_eq!(
            prompter.ask_identifier().await.expect_err("input ended"),
            Abort::InputEnded
        );
    }

    #[test]
    fn failure_texts_are_fixed_and_name_the_amazon_workaround_for_a_refused_start() {
        assert!(login_failure_text(&LoginError::RefusedStart).contains("Amazon"));
        assert!(
            login_failure_text(&LoginError::RateLimited {
                retry_after_seconds: Some(30)
            })
            .contains("30 seconds")
        );
        let budget = login_failure_text(&LoginError::StartBudgetExhausted {
            retry_after_seconds: 42,
        });
        assert!(
            budget.contains("42 seconds") && budget.contains("Nothing was sent"),
            "{budget}"
        );
        for error in [
            LoginError::CodeRejected,
            LoginError::VerificationRefused,
            LoginError::TooManyInvalidIdentifiers,
            LoginError::Network,
            LoginError::Timeout,
            LoginError::UnusableToken,
            LoginError::Other,
            LoginError::Aborted(Abort::InputEnded),
            LoginError::Aborted(Abort::Cancelled),
        ] {
            assert!(!login_failure_text(&error).is_empty(), "{error:?}");
        }
    }
}
