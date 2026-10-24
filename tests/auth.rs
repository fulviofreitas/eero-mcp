//! The login driver, eero-mcp's own credential store and logout, through the library's public API.
//!
//! These are integration tests rather than an in-module block on purpose: the read-only guard
//! scans `src/auth.rs` whole, test module included, and bans there the in-memory store, any store
//! load and any mock server. Here every mock eero comes from `common::mock_cloud()` (write
//! tripwire mounted: a login, resend, verify or logout request that a test did not mount fails the
//! test), the keyring is a stand-in (rusteero's in-memory store paired with a fake keyring source
//! that reads it) and the own file lives in a temporary directory.
//!
//! No test reaches the real keyring, the user's eeroctl file or the real eero-mcp directory, and
//! no test sends a request anywhere but the local mock. Values are synthetic: identifier
//! `user@example.com`, codes `000001` and `000002`, login tokens `login-token-0001` and `-0002`.

mod common;

use std::collections::VecDeque;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{
    CODE, CODE_2, IDENTIFIER, LOGIN_TOKEN, LOGIN_TOKEN_2, mock_cloud, mount_logout, mount_resend,
    mount_resend_status, mount_start, mount_start_error, mount_verify_error, mount_verify_ok,
    targets_of,
};
use eero_mcp::auth::{
    Abort, CodeKind, LoginError, NotChecked, OwnStore, Problem, Prompter, SaveError, StartBudget,
    StoreKind, revoke_replaced, revoke_session, run_login, save_session, sign_out_own_session,
};
use eero_mcp::cli::{self, Line, LineSource};
use eero_mcp::config::{EnvMap, Settings};
use eero_mcp::credentials::{CredentialChain, Source, SystemSources};
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;
use tokio::sync::Semaphore;
use wiremock::MockServer;

// ===================== fixtures =====================

/// A scripted answer.
#[derive(Clone)]
enum Answer {
    Text(&'static str),
    Owned(String),
    Abort(Abort),
    /// The user never answers.
    Never,
}

/// A prompter that answers from a script and records what it was asked.
struct Script {
    identifiers: VecDeque<Answer>,
    codes: VecDeque<Answer>,
    identifiers_asked: usize,
    codes_asked: Vec<CodeKind>,
    problems: Vec<Problem>,
    permits: Option<Arc<Semaphore>>,
    /// The permits free whenever the prompter was asked something.
    free_when_asked: Vec<usize>,
    /// Signalled whenever the prompter is asked for a code.
    code_asked: Option<Arc<tokio::sync::Notify>>,
}

impl Script {
    fn new(identifiers: &[Answer], codes: &[Answer]) -> Self {
        Self {
            identifiers: identifiers.iter().cloned().collect(),
            codes: codes.iter().cloned().collect(),
            identifiers_asked: 0,
            codes_asked: Vec::new(),
            problems: Vec::new(),
            permits: None,
            free_when_asked: Vec::new(),
            code_asked: None,
        }
    }

    /// The identifier form answered once, then the given code answers.
    fn answering(codes: &[&'static str]) -> Self {
        let codes: Vec<Answer> = codes.iter().map(|code| Answer::Text(code)).collect();
        Self::new(&[Answer::Text(IDENTIFIER)], &codes)
    }

    fn note_permits(&mut self) {
        if let Some(permits) = &self.permits {
            self.free_when_asked.push(permits.available_permits());
        }
    }
}

async fn answer(next: Option<Answer>) -> Result<SecretString, Abort> {
    match next.expect("one scripted answer per question") {
        Answer::Text(text) => Ok(SecretString::from(text.to_owned())),
        Answer::Owned(text) => Ok(SecretString::from(text)),
        Answer::Abort(abort) => Err(abort),
        Answer::Never => std::future::pending().await,
    }
}

impl Prompter for Script {
    fn ask_identifier(&mut self) -> impl Future<Output = Result<SecretString, Abort>> + Send {
        self.identifiers_asked += 1;
        self.note_permits();
        answer(self.identifiers.pop_front())
    }

    fn ask_code(
        &mut self,
        kind: CodeKind,
    ) -> impl Future<Output = Result<SecretString, Abort>> + Send {
        self.codes_asked.push(kind);
        self.note_permits();
        if let Some(signal) = &self.code_asked {
            signal.notify_one();
        }
        answer(self.codes.pop_front())
    }

    fn report(&mut self, problem: Problem) -> impl Future<Output = ()> + Send {
        self.problems.push(problem);
        std::future::ready(())
    }
}

/// A mock eero, a temporary directory and the settings that point the library at both.
struct Fixture {
    mock: MockServer,
    dir: TempDir,
}

impl Fixture {
    async fn new() -> Self {
        Self {
            mock: mock_cloud().await,
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn origin(&self) -> String {
        self.mock.uri()
    }

    /// The own directory (not created until a save needs it).
    fn own_dir(&self) -> PathBuf {
        self.dir.path().join("cfg")
    }

    fn own_file(&self) -> PathBuf {
        self.own_dir().join("session.json")
    }

    /// eeroctl's default file in this fixture.
    fn eeroctl_file(&self) -> PathBuf {
        self.dir.path().join("eeroctl").join("cookies.json")
    }

    /// Settings with the own directory in the temporary directory, the keyring switched off, the
    /// base URL on the mock and eeroctl's directory in the temporary directory.
    fn settings(&self, extra: &[(&str, &str)]) -> Settings {
        self.settings_with_keyring(false, extra)
    }

    fn settings_with_keyring(&self, keyring: bool, extra: &[(&str, &str)]) -> Settings {
        let mut pairs: Vec<(String, String)> = vec![
            (
                "EERO_MCP_CONFIG_DIR".to_owned(),
                self.own_dir().to_str().expect("utf-8").to_owned(),
            ),
            ("EERO_MCP_API_BASE_URL".to_owned(), self.origin()),
            (
                "EEROCTL_CONFIG_DIR".to_owned(),
                self.dir
                    .path()
                    .join("eeroctl")
                    .to_str()
                    .expect("utf-8")
                    .to_owned(),
            ),
        ];
        if !keyring {
            pairs.push(("EERO_MCP_NO_KEYRING".to_owned(), "1".to_owned()));
        }
        pairs.extend(
            extra
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
        );
        Settings::from_env_for(&EnvMap::from_pairs(pairs), false).expect("valid settings")
    }

    /// The chain over the real file sources, with the keyring off.
    #[allow(clippy::unused_self)]
    fn chain(&self, settings: &Settings) -> Arc<CredentialChain> {
        Arc::new(CredentialChain::new(settings, Arc::new(SystemSources)))
    }
}

fn token(value: &str) -> SecretString {
    SecretString::from(value.to_owned())
}

fn record(token: &str) -> String {
    format!(r#"{{"session_id":"{token}","schema_version":2}}"#)
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).expect("readable file")
}

/// The login driver against the fixture's mock.
async fn login(
    fx: &Fixture,
    script: &mut Script,
    identifier: Option<&str>,
) -> Result<String, LoginError> {
    let permits = Arc::new(Semaphore::new(1));
    script.permits = Some(Arc::clone(&permits));
    run_login(
        Some(&fx.origin()),
        identifier.map(token),
        script,
        Some(&permits),
        &StartBudget::standard(),
    )
    .await
    .map(|token| token.expose_secret().to_owned())
}

// ===================== the driver =====================

#[tokio::test]
async fn a_login_asks_for_the_identifier_and_the_code_and_returns_the_verified_token()
-> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 1).await;
    let mut script = Script::answering(&[CODE]);

    let session = login(&fx, &mut script, None).await;

    assert_eq!(session, Ok(LOGIN_TOKEN.to_owned()));
    assert_eq!(script.identifiers_asked, 1);
    assert_eq!(script.codes_asked, [CodeKind::First]);
    assert!(script.problems.is_empty());
    assert_eq!(
        targets_of(&fx.mock).await,
        ["POST /2.2/login", "POST /2.2/login/verify"]
    );
    Ok(())
}

#[tokio::test]
async fn surrounding_whitespace_is_trimmed_from_both_answers() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 1).await;
    let mut script = Script::new(
        &[Answer::Text("  user@example.com \t")],
        &[Answer::Text(" 000001 ")],
    );
    assert_eq!(
        login(&fx, &mut script, None).await,
        Ok(LOGIN_TOKEN.to_owned())
    );
    Ok(())
}

#[tokio::test]
async fn a_given_identifier_is_not_asked_for() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 1).await;
    let mut script = Script::new(&[], &[Answer::Text(CODE)]);

    assert_eq!(
        login(&fx, &mut script, Some(IDENTIFIER)).await,
        Ok(LOGIN_TOKEN.to_owned())
    );
    assert_eq!(script.identifiers_asked, 0);
    Ok(())
}

#[tokio::test]
async fn an_empty_answer_and_new_resend_the_code_and_the_resend_limit_holds() -> anyhow::Result<()>
{
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    // Three resends are sent; the fourth request for one is refused locally.
    mount_resend(&fx.mock, LOGIN_TOKEN, 3).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 1).await;
    let mut script = Script::answering(&["", "new", "NEW", " New ", CODE]);

    assert_eq!(
        login(&fx, &mut script, None).await,
        Ok(LOGIN_TOKEN.to_owned())
    );

    assert_eq!(
        script.codes_asked,
        [
            CodeKind::First,
            CodeKind::Resent,
            CodeKind::Resent,
            CodeKind::Resent,
            CodeKind::Resent
        ]
    );
    assert_eq!(script.problems, [Problem::ResendLimit]);
    assert_eq!(
        targets_of(&fx.mock).await,
        [
            "POST /2.2/login",
            "POST /2.2/login/resend",
            "POST /2.2/login/resend",
            "POST /2.2/login/resend",
            "POST /2.2/login/verify"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_resend_is_reported_counted_and_asked_again() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_resend_status(&fx.mock, LOGIN_TOKEN, 500, None, 1).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 1).await;
    let mut script = Script::answering(&["new", CODE]);

    assert_eq!(
        login(&fx, &mut script, None).await,
        Ok(LOGIN_TOKEN.to_owned())
    );
    assert_eq!(script.problems, [Problem::ResendFailed]);
    // The code was not resent, so it is still the first one.
    assert_eq!(script.codes_asked, [CodeKind::First, CodeKind::First]);
    Ok(())
}

#[tokio::test]
async fn a_rate_limited_resend_ends_the_login() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_resend_status(&fx.mock, LOGIN_TOKEN, 429, Some("7"), 1).await;
    let mut script = Script::answering(&["new"]);

    assert_eq!(
        login(&fx, &mut script, None).await,
        Err(LoginError::RateLimited {
            retry_after_seconds: Some(7)
        })
    );
    Ok(())
}

#[tokio::test]
async fn invalid_identifier_entries_are_reported_and_the_third_in_a_row_ends_the_login()
-> anyhow::Result<()> {
    let fx = Fixture::new().await;
    // Two bad entries, then a good one: the login goes ahead.
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 1).await;
    let mut script = Script::new(
        &[
            Answer::Text(""),
            Answer::Text("bad\u{0}identifier"),
            Answer::Text(IDENTIFIER),
        ],
        &[Answer::Text(CODE)],
    );
    assert_eq!(
        login(&fx, &mut script, None).await,
        Ok(LOGIN_TOKEN.to_owned())
    );
    assert_eq!(
        script.problems,
        [Problem::InvalidIdentifier, Problem::InvalidIdentifier]
    );

    // Three in a row end it without a request.
    let other = Fixture::new().await;
    let mut script = Script::new(
        &[
            Answer::Text(""),
            Answer::Text("   "),
            Answer::Owned("x".repeat(255)),
        ],
        &[],
    );
    assert_eq!(
        login(&other, &mut script, None).await,
        Err(LoginError::TooManyInvalidIdentifiers)
    );
    assert_eq!(
        script.problems,
        [Problem::InvalidIdentifier, Problem::InvalidIdentifier]
    );
    assert!(targets_of(&other.mock).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn malformed_codes_are_reported_without_a_request() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 1).await;
    let long = "9".repeat(33);
    let mut script = Script::new(
        &[Answer::Text(IDENTIFIER)],
        &[
            Answer::Text("00 00 01"),
            Answer::Owned(long),
            Answer::Text(CODE),
        ],
    );

    assert_eq!(
        login(&fx, &mut script, None).await,
        Ok(LOGIN_TOKEN.to_owned())
    );
    assert_eq!(
        script.problems,
        [Problem::MalformedCode, Problem::MalformedCode]
    );
    // One start and one verify: the malformed entries sent nothing.
    assert_eq!(targets_of(&fx.mock).await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_wrong_code_restarts_the_login_with_a_new_code() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    // Two starts, each with its own login token: the first code is wrong.
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN_2, 1).await;
    mount_verify_error(
        &fx.mock,
        LOGIN_TOKEN,
        CODE,
        401,
        Some("error.verification.invalid"),
        1,
    )
    .await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN_2, CODE_2, 1).await;
    let mut script = Script::answering(&[CODE, CODE_2]);

    assert_eq!(
        login(&fx, &mut script, None).await,
        Ok(LOGIN_TOKEN_2.to_owned())
    );

    assert_eq!(script.codes_asked, [CodeKind::First, CodeKind::New]);
    assert_eq!(script.identifiers_asked, 1, "the identifier is kept");
    assert_eq!(
        targets_of(&fx.mock).await,
        [
            "POST /2.2/login",
            "POST /2.2/login/verify",
            "POST /2.2/login",
            "POST /2.2/login/verify"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn three_rejected_codes_end_the_login_after_three_starts() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 3).await;
    mount_verify_error(
        &fx.mock,
        LOGIN_TOKEN,
        CODE,
        401,
        Some("error.verification.invalid"),
        3,
    )
    .await;
    let mut script = Script::answering(&[CODE, CODE, CODE]);

    assert_eq!(
        login(&fx, &mut script, None).await,
        Err(LoginError::CodeRejected)
    );
    assert_eq!(
        script.codes_asked,
        [CodeKind::First, CodeKind::New, CodeKind::New]
    );
    Ok(())
}

#[tokio::test]
async fn a_wrong_expired_unlabelled_or_malformed_code_all_restart_the_login() -> anyhow::Result<()>
{
    // (status, eero's error code): the shapes of a rejected code.
    let rejections: [(u16, Option<&str>); 4] = [
        (401, Some("error.verification.invalid")),
        (401, Some("error.verification.expired")),
        (401, None),
        // eero refusing the code's format is a validation error; the consumed pending login
        // leaves only a new start.
        (400, Some("error.form.errors")),
    ];
    for (status, error) in rejections {
        let fx = Fixture::new().await;
        mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
        mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN_2, 1).await;
        mount_verify_error(&fx.mock, LOGIN_TOKEN, CODE, status, error, 1).await;
        mount_verify_ok(&fx.mock, LOGIN_TOKEN_2, CODE_2, 1).await;
        let mut script = Script::answering(&[CODE, CODE_2]);
        assert_eq!(
            login(&fx, &mut script, None).await,
            Ok(LOGIN_TOKEN_2.to_owned()),
            "{status} {error:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_refused_verification_ends_the_login_after_one_start() -> anyhow::Result<()> {
    // The rest of eero's verification group, and a re-wrapped API error that carries an eero error
    // code: a new start would send the user another message, so none is made.
    let refusals: [(u16, Option<&str>); 8] = [
        (401, Some("error.verification.blocked")),
        (401, Some("error.verification.failure")),
        (401, Some("error.verification.required")),
        (401, Some("error.login.blocked")),
        (401, Some("error.login.unknown")),
        (401, Some("error.too.many.resends")),
        (401, Some("error.email.unverified")),
        (403, Some("error.access.denied")),
    ];
    for (status, error) in refusals {
        let fx = Fixture::new().await;
        mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
        mount_verify_error(&fx.mock, LOGIN_TOKEN, CODE, status, error, 1).await;
        let mut script = Script::answering(&[CODE, CODE_2]);
        assert_eq!(
            login(&fx, &mut script, None).await,
            Err(LoginError::VerificationRefused),
            "{status} {error:?}"
        );
        assert_eq!(script.codes_asked, [CodeKind::First], "{status} {error:?}");
        assert_eq!(targets_of(&fx.mock).await.len(), 2, "{status} {error:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_refused_start_ends_the_login_before_any_code_is_asked() -> anyhow::Result<()> {
    for (status, error) in [
        (400, "error.user.amazon_login.exists"),
        (404, "error.login.unknown"),
        (403, "error.access.denied"),
    ] {
        let fx = Fixture::new().await;
        mount_start_error(&fx.mock, IDENTIFIER, status, error, 1).await;
        let mut script = Script::answering(&[CODE]);
        assert_eq!(
            login(&fx, &mut script, None).await,
            Err(LoginError::RefusedStart),
            "{status} {error}"
        );
        assert!(script.codes_asked.is_empty(), "{status} {error}");
    }
    Ok(())
}

#[tokio::test]
async fn a_verification_failure_without_a_status_or_an_eero_code_is_the_generic_failure()
-> anyhow::Result<()> {
    // A 5xx from eero is re-wrapped without a status and with no error code: it says nothing about
    // the account, so it must not read as "eero refused the verification".
    for status in [500u16, 502, 503] {
        let fx = Fixture::new().await;
        mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
        mount_verify_error(&fx.mock, LOGIN_TOKEN, CODE, status, None, 1).await;
        let mut script = Script::answering(&[CODE, CODE_2]);
        assert_eq!(
            login(&fx, &mut script, None).await,
            Err(LoginError::Other),
            "{status}"
        );
        // Ended at once: no second code, no restart.
        assert_eq!(script.codes_asked, [CodeKind::First], "{status}");
        assert_eq!(targets_of(&fx.mock).await.len(), 2, "{status}");
    }
    Ok(())
}

// ===================== the start budget =====================

#[test]
fn the_budget_admits_its_limit_and_then_says_how_long_to_wait() {
    let window = Duration::from_mins(15);
    let budget = StartBudget::with_limit(3, window);
    let t0 = tokio::time::Instant::now();
    for step in 0..3u64 {
        assert_eq!(budget.take_at(t0 + Duration::from_secs(step * 10)), Ok(()));
    }
    // The oldest start (t0) leaves the window at t0 + 900 s.
    assert_eq!(
        budget.take_at(t0 + Duration::from_secs(30)),
        Err(LoginError::StartBudgetExhausted {
            retry_after_seconds: 870
        })
    );
    // A refused start is not counted and does not move the window.
    assert_eq!(
        budget.take_at(t0 + Duration::from_secs(31)),
        Err(LoginError::StartBudgetExhausted {
            retry_after_seconds: 869
        })
    );
    // The window slides: when the first start leaves, exactly one more is admitted.
    assert_eq!(budget.take_at(t0 + window), Ok(()));
    assert_eq!(
        budget.take_at(t0 + window + Duration::from_secs(1)),
        Err(LoginError::StartBudgetExhausted {
            retry_after_seconds: 9
        })
    );
    assert_eq!(
        budget.take_at(t0 + window + Duration::from_secs(10)),
        Ok(())
    );
}

#[test]
fn the_wait_is_rounded_up_to_whole_seconds_and_is_at_least_one() {
    let budget = StartBudget::with_limit(1, Duration::from_mins(15));
    let t0 = tokio::time::Instant::now();
    assert_eq!(budget.take_at(t0), Ok(()));
    for (elapsed, wait) in [
        (Duration::from_millis(899_400), 1),
        (Duration::from_millis(899_999), 1),
        (Duration::from_millis(100_001), 800),
        (Duration::from_secs(1), 899),
    ] {
        assert_eq!(
            budget.take_at(t0 + elapsed),
            Err(LoginError::StartBudgetExhausted {
                retry_after_seconds: wait
            }),
            "{elapsed:?}"
        );
    }
}

#[test]
fn checking_the_budget_takes_nothing_and_a_zero_budget_never_admits() {
    let budget = StartBudget::with_limit(1, Duration::from_mins(15));
    assert_eq!(budget.check(), Ok(()));
    assert_eq!(budget.check(), Ok(()));
    assert_eq!(budget.take(), Ok(()));
    assert!(matches!(
        budget.check(),
        Err(LoginError::StartBudgetExhausted { .. })
    ));
    assert!(matches!(
        budget.take(),
        Err(LoginError::StartBudgetExhausted { .. })
    ));

    let none = StartBudget::with_limit(0, Duration::from_mins(15));
    assert_eq!(
        none.take(),
        Err(LoginError::StartBudgetExhausted {
            retry_after_seconds: 900
        })
    );
    // The production budget is three starts in fifteen minutes.
    assert_eq!(eero_mcp::auth::START_BUDGET, 3);
    assert_eq!(eero_mcp::auth::START_WINDOW, Duration::from_mins(15));
    let standard = StartBudget::standard();
    for _ in 0..3 {
        assert_eq!(standard.take(), Ok(()));
    }
    assert!(standard.take().is_err());
}

#[tokio::test]
async fn an_exhausted_budget_sends_nothing_and_does_not_even_ask_for_the_identifier()
-> anyhow::Result<()> {
    let fx = Fixture::new().await;
    let budget = StartBudget::with_limit(0, Duration::from_mins(15));
    let mut script = Script::answering(&[CODE]);

    let result = run_login(Some(&fx.origin()), None, &mut script, None, &budget).await;

    assert_eq!(
        result.map(|token| token.expose_secret().to_owned()),
        Err(LoginError::StartBudgetExhausted {
            retry_after_seconds: 900
        })
    );
    assert_eq!(
        script.identifiers_asked, 0,
        "no form for a login that cannot start"
    );
    assert!(script.codes_asked.is_empty());
    assert!(targets_of(&fx.mock).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_restart_after_a_rejected_code_takes_a_start_from_the_budget() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    // One start is allowed. The first code is rejected; the restart is refused and sends nothing.
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_error(
        &fx.mock,
        LOGIN_TOKEN,
        CODE,
        401,
        Some("error.verification.invalid"),
        1,
    )
    .await;
    let budget = StartBudget::with_limit(1, Duration::from_mins(15));
    let mut script = Script::answering(&[CODE, CODE_2]);

    let result = run_login(Some(&fx.origin()), None, &mut script, None, &budget).await;

    assert!(matches!(
        result,
        Err(LoginError::StartBudgetExhausted { .. })
    ));
    assert_eq!(
        script.codes_asked,
        [CodeKind::First],
        "no second code was asked for"
    );
    assert_eq!(
        targets_of(&fx.mock).await,
        ["POST /2.2/login", "POST /2.2/login/verify"]
    );
    Ok(())
}

#[tokio::test]
async fn the_budget_is_shared_by_every_run_and_a_refused_run_sends_nothing() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 3).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 3).await;
    let budget = StartBudget::standard();
    for run in 0..3 {
        let mut script = Script::answering(&[CODE]);
        let result = run_login(
            Some(&fx.origin()),
            Some(token(IDENTIFIER)),
            &mut script,
            None,
            &budget,
        )
        .await;
        assert!(result.is_ok(), "run {run} is within the budget");
    }
    assert_eq!(targets_of(&fx.mock).await.len(), 6);

    let mut script = Script::answering(&[CODE]);
    let result = run_login(
        Some(&fx.origin()),
        Some(token(IDENTIFIER)),
        &mut script,
        None,
        &budget,
    )
    .await;
    assert!(matches!(
        result,
        Err(LoginError::StartBudgetExhausted { retry_after_seconds }) if (1..=900).contains(&retry_after_seconds)
    ));
    assert!(script.codes_asked.is_empty());
    assert_eq!(
        targets_of(&fx.mock).await.len(),
        6,
        "the fourth run sent nothing"
    );
    Ok(())
}

#[tokio::test]
async fn rate_limits_network_failures_and_the_prompter_giving_up_end_the_login()
-> anyhow::Result<()> {
    // A rate-limited start carries the wait.
    let fx = Fixture::new().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/2.2/login"))
        .respond_with(
            wiremock::ResponseTemplate::new(429)
                .insert_header("Retry-After", "30")
                .set_body_raw("{}", "application/json"),
        )
        .with_priority(1)
        .expect(1)
        .mount(&fx.mock)
        .await;
    let mut script = Script::answering(&[CODE]);
    assert_eq!(
        login(&fx, &mut script, None).await,
        Err(LoginError::RateLimited {
            retry_after_seconds: Some(30)
        })
    );

    // A refused connection: a loopback port nothing listens on.
    let mut script = Script::answering(&[CODE]);
    let result = run_login(
        Some("http://127.0.0.1:1"),
        None,
        &mut script,
        None,
        &StartBudget::standard(),
    )
    .await
    .map(|token| token.expose_secret().to_owned());
    assert_eq!(result, Err(LoginError::Network));

    // The prompter gives up before and after the start.
    let quiet = Fixture::new().await;
    let mut script = Script::new(&[Answer::Abort(Abort::InputEnded)], &[]);
    assert_eq!(
        login(&quiet, &mut script, None).await,
        Err(LoginError::Aborted(Abort::InputEnded))
    );
    assert!(targets_of(&quiet.mock).await.is_empty());

    let quiet = Fixture::new().await;
    mount_start(&quiet.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    let mut script = Script::new(
        &[Answer::Text(IDENTIFIER)],
        &[Answer::Abort(Abort::Cancelled)],
    );
    assert_eq!(
        login(&quiet, &mut script, None).await,
        Err(LoginError::Aborted(Abort::Cancelled))
    );
    assert_eq!(targets_of(&quiet.mock).await, ["POST /2.2/login"]);
    Ok(())
}

#[tokio::test]
async fn a_permit_is_held_for_each_request_and_never_while_the_prompter_waits() -> anyhow::Result<()>
{
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_resend(&fx.mock, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 1).await;
    let mut script = Script::answering(&["new", CODE]);

    let permits = Arc::new(Semaphore::new(1));
    script.permits = Some(Arc::clone(&permits));
    run_login(
        Some(&fx.origin()),
        None,
        &mut script,
        Some(&permits),
        &StartBudget::standard(),
    )
    .await
    .expect("the login succeeds");

    // Asked for the identifier and twice for the code, each time with the one permit free.
    assert_eq!(script.free_when_asked, [1, 1, 1]);
    assert_eq!(permits.available_permits(), 1, "every permit is released");

    // With no permit to be had, the login waits instead of sending anything.
    let blocked = Fixture::new().await;
    let none = Semaphore::new(0);
    let mut script = Script::answering(&[CODE]);
    let waiting = tokio::time::timeout(
        Duration::from_millis(200),
        run_login(
            Some(&blocked.origin()),
            None,
            &mut script,
            Some(&none),
            &StartBudget::standard(),
        ),
    )
    .await;
    assert!(waiting.is_err(), "the start waits for a permit");
    assert!(targets_of(&blocked.mock).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn abandoning_the_login_stops_it_at_once_and_sends_nothing_more() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    // The user never answers the code form.
    let mut script = Script::new(&[Answer::Text(IDENTIFIER)], &[Answer::Never]);
    let asked = Arc::new(tokio::sync::Notify::new());
    script.code_asked = Some(Arc::clone(&asked));

    // Wait until the start has been sent and the code is being asked for, then abandon the
    // login by dropping its future.
    tokio::select! {
        outcome = login(&fx, &mut script, None) => panic!("the login cannot finish: {outcome:?}"),
        () = asked.notified() => {}
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(targets_of(&fx.mock).await, ["POST /2.2/login"]);
    Ok(())
}

#[tokio::test]
async fn no_error_text_carries_the_identifier_or_the_code() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_error(
        &fx.mock,
        LOGIN_TOKEN,
        CODE,
        403,
        Some("error.access.denied"),
        1,
    )
    .await;
    let mut script = Script::answering(&[CODE]);
    let error = login(&fx, &mut script, None).await.expect_err("refused");
    let text = format!("{error:?}");
    assert!(!text.contains(IDENTIFIER) && !text.contains(CODE), "{text}");
    Ok(())
}

// ===================== the own store =====================

#[tokio::test]
async fn saving_to_the_file_alone_reports_the_file_and_writes_the_eero_api_record()
-> anyhow::Result<()> {
    let fx = Fixture::new().await;
    let settings = fx.settings(&[]);
    let chain = fx.chain(&settings);
    let store = OwnStore::production(&settings);
    assert!(store.has_backend());
    assert_eq!(store.file_path(), Some(fx.own_file().as_path()));

    let saved = save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;

    assert_eq!(saved.kind, StoreKind::File);
    assert_eq!(saved.replaced_count(), 0, "nothing was replaced");
    let saved: serde_json::Value = serde_json::from_str(&read(&fx.own_file()))?;
    assert_eq!(saved["session_id"], LOGIN_TOKEN);
    assert_eq!(saved["schema_version"], 2);
    // The server's chain now resolves to the saved session, by the own file's name.
    let resolved = chain.startup_resolved().expect("ok").expect("a hit");
    assert_eq!(resolved.source, Source::OwnFile);
    assert_eq!(resolved.token.expose_secret(), LOGIN_TOKEN);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn the_file_is_created_0600_in_a_0700_directory_the_save_creates() -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let fx = Fixture::new().await;
    // Two missing levels: the save creates both.
    let nested = fx.dir.path().join("a").join("b");
    let settings = fx.settings(&[("EERO_MCP_CONFIG_DIR", nested.to_str().expect("utf-8"))]);
    let chain = fx.chain(&settings);
    save_session(
        &OwnStore::production(&settings),
        &chain,
        &token(LOGIN_TOKEN),
    )
    .await?;

    let mode = |path: &Path| {
        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    };
    assert_eq!(mode(&nested.join("session.json")), 0o600);
    assert_eq!(mode(&nested), 0o700);
    assert_eq!(mode(&fx.dir.path().join("a")), 0o700);
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn a_symlink_at_the_own_path_is_replaced_on_save_and_removed_on_clear_never_followed()
-> anyhow::Result<()> {
    let fx = Fixture::new().await;
    let settings = fx.settings(&[]);
    let chain = fx.chain(&settings);
    let store = OwnStore::production(&settings);

    // The link points at a file that must stay exactly as it is.
    let target = fx.dir.path().join("precious.json");
    std::fs::write(&target, "precious bytes")?;
    std::fs::create_dir_all(fx.own_dir())?;
    std::os::unix::fs::symlink(&target, fx.own_file())?;

    save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;
    assert!(
        !std::fs::symlink_metadata(fx.own_file())?
            .file_type()
            .is_symlink(),
        "the link itself was replaced by a regular file"
    );
    assert_eq!(read(&target), "precious bytes", "the target is untouched");
    assert!(read(&fx.own_file()).contains(LOGIN_TOKEN));

    // And a link planted afterwards is removed by a clear, not followed.
    std::fs::remove_file(fx.own_file())?;
    std::os::unix::fs::symlink(&target, fx.own_file())?;
    let cleared = store.clear_all().await;
    assert_eq!(cleared.file, Some(true));
    assert!(
        std::fs::symlink_metadata(fx.own_file()).is_err(),
        "the link is gone"
    );
    assert_eq!(
        read(&target),
        "precious bytes",
        "the target survives the clear"
    );
    Ok(())
}

#[tokio::test]
async fn a_save_that_cannot_write_fails_with_fixed_text() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    // The own directory is a regular file, so no directory can be created under it.
    let blocked = fx.dir.path().join("blocked");
    std::fs::write(&blocked, "not a directory")?;
    let settings = fx.settings(&[("EERO_MCP_CONFIG_DIR", blocked.to_str().expect("utf-8"))]);
    let chain = fx.chain(&settings);

    let error = save_session(
        &OwnStore::production(&settings),
        &chain,
        &token(LOGIN_TOKEN),
    )
    .await
    .expect_err("the save fails");

    assert!(
        matches!(
            error,
            SaveError::Io | SaveError::NotRetained | SaveError::Other
        ),
        "{error:?}"
    );
    let text = error.describe();
    assert!(!text.contains(LOGIN_TOKEN) && !text.contains(blocked.to_str().expect("utf-8")));
    assert_eq!(
        read(&blocked),
        "not a directory",
        "the blocker is untouched"
    );
    Ok(())
}

#[tokio::test]
async fn with_no_keyring_and_no_directory_there_is_nowhere_to_save() -> anyhow::Result<()> {
    let settings =
        Settings::from_env_for(&EnvMap::from_pairs([("EERO_MCP_NO_KEYRING", "1")]), false)?;
    let store = OwnStore::production(&settings);
    assert!(!store.has_backend());
    assert!(store.file_path().is_none());
    let chain = Arc::new(CredentialChain::new(&settings, Arc::new(SystemSources)));
    assert_eq!(
        save_session(&store, &chain, &token(LOGIN_TOKEN))
            .await
            .expect_err("nowhere to save"),
        SaveError::NoLocation
    );
    assert!(
        SaveError::NoLocation
            .describe()
            .contains("EERO_MCP_CONFIG_DIR")
    );
    Ok(())
}

#[tokio::test]
async fn the_save_error_texts_are_fixed_and_the_store_debug_prints_no_path() {
    for error in [
        SaveError::NoLocation,
        SaveError::NotRetained,
        SaveError::Backend,
        SaveError::Io,
        SaveError::Shadowed,
        SaveError::Other,
    ] {
        assert!(!error.describe().is_empty());
    }
    let store = OwnStore::with_backends(
        None,
        Some(PathBuf::from("/home/someone/secret-dir/session.json")),
    );
    assert!(!format!("{store:?}").contains("secret-dir"));
}

#[tokio::test]
async fn clearing_removes_the_file_and_a_missing_record_is_fine() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    let settings = fx.settings(&[]);
    let chain = fx.chain(&settings);
    let store = OwnStore::production(&settings);

    let nothing = store.clear_all().await;
    assert_eq!(nothing.file, Some(true));
    assert_eq!(nothing.keyring, None);

    save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;
    assert!(fx.own_file().exists());
    assert_eq!(store.clear_all().await.file, Some(true));
    assert!(!fx.own_file().exists());
    Ok(())
}

// ===================== logging in again =====================

#[tokio::test]
async fn logging_in_again_signs_the_replaced_session_out_once_the_new_one_is_stored()
-> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_logout(&fx.mock, LOGIN_TOKEN, 1).await;
    let settings = fx.settings(&[]);
    let chain = fx.chain(&settings);
    let store = OwnStore::production(&settings);
    let base = settings.api_base_url.as_deref();

    let first = save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;
    assert_eq!(first.replaced_count(), 0);
    // Nothing replaced, nothing sent.
    let outcome = revoke_replaced(base, &chain, first).await;
    assert_eq!(
        (outcome.revoked, outcome.held_elsewhere, outcome.not_sent),
        (0, 0, 0)
    );
    assert!(targets_of(&fx.mock).await.is_empty());

    let second = save_session(&store, &chain, &token(LOGIN_TOKEN_2)).await?;
    assert_eq!(second.replaced_count(), 1);
    // The value that carries the replaced token prints no token.
    let shown = format!("{second:?}");
    assert!(
        !shown.contains(LOGIN_TOKEN) && !shown.contains(LOGIN_TOKEN_2),
        "{shown}"
    );
    assert!(
        read(&fx.own_file()).contains(LOGIN_TOKEN_2),
        "the new session is stored first"
    );
    assert!(
        targets_of(&fx.mock).await.is_empty(),
        "saving alone sends nothing"
    );

    let outcome = revoke_replaced(base, &chain, second).await;
    assert_eq!(
        (outcome.revoked, outcome.held_elsewhere, outcome.not_sent),
        (1, 0, 0)
    );
    assert_eq!(targets_of(&fx.mock).await, ["POST /2.2/logout"]);
    assert!(read(&fx.own_file()).contains(LOGIN_TOKEN_2));
    Ok(())
}

#[tokio::test]
async fn saving_the_session_that_is_already_stored_replaces_nothing() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    let settings = fx.settings(&[]);
    let chain = fx.chain(&settings);
    let store = OwnStore::production(&settings);
    save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;

    let again = save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;

    assert_eq!(
        again.replaced_count(),
        0,
        "signing it out would end the new login"
    );
    let outcome = revoke_replaced(settings.api_base_url.as_deref(), &chain, again).await;
    assert_eq!(outcome.revoked, 0);
    assert!(targets_of(&fx.mock).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_replaced_session_another_source_holds_is_not_signed_out() -> anyhow::Result<()> {
    for holder in ["eeroctl file", "environment token", "explicit file"] {
        let fx = Fixture::new().await;
        let explicit = fx.dir.path().join("explicit.json");
        let extra: Vec<(&str, String)> = match holder {
            "environment token" => vec![("RUSTEERO_SESSION_TOKEN", LOGIN_TOKEN.to_owned())],
            "explicit file" => vec![(
                "EERO_MCP_SESSION_FILE",
                explicit.to_str().expect("utf-8").to_owned(),
            )],
            _ => vec![],
        };
        let extra_refs: Vec<(&str, &str)> = extra.iter().map(|(a, b)| (*a, b.as_str())).collect();
        let settings = fx.settings(&extra_refs);
        let chain = fx.chain(&settings);
        let store = OwnStore::production(&settings);

        // The own file and the other source hold the same, older session.
        let shared = record(LOGIN_TOKEN);
        std::fs::create_dir_all(fx.own_dir())?;
        std::fs::write(fx.own_file(), &shared)?;
        match holder {
            "eeroctl file" => {
                std::fs::create_dir_all(fx.eeroctl_file().parent().expect("parent"))?;
                std::fs::write(fx.eeroctl_file(), &shared)?;
            }
            "explicit file" => std::fs::write(&explicit, &shared)?,
            _ => {}
        }

        let saved = save_session(&store, &chain, &token(LOGIN_TOKEN_2)).await?;
        assert_eq!(saved.replaced_count(), 1, "{holder}");
        let outcome = revoke_replaced(settings.api_base_url.as_deref(), &chain, saved).await;

        assert_eq!(
            (outcome.revoked, outcome.held_elsewhere, outcome.not_sent),
            (0, 1, 0),
            "{holder}"
        );
        assert!(
            targets_of(&fx.mock).await.is_empty(),
            "{holder}: no sign-out"
        );
        match holder {
            "eeroctl file" => assert_eq!(read(&fx.eeroctl_file()), shared),
            "explicit file" => assert_eq!(read(&explicit), shared),
            _ => {}
        }
    }
    Ok(())
}

// ===================== logout =====================

#[tokio::test]
async fn logout_with_nothing_stored_sends_nothing_and_succeeds() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    let settings = fx.settings(&[]);
    let chain = fx.chain(&settings);

    let report = sign_out_own_session(
        settings.api_base_url.as_deref(),
        &OwnStore::production(&settings),
        &chain,
    )
    .await;

    assert!(report.found.is_empty());
    assert!(report.revoked.is_empty() && report.removed.is_empty());
    assert!(report.ok());
    assert!(targets_of(&fx.mock).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn logout_signs_the_stored_session_out_and_then_deletes_it() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_logout(&fx.mock, LOGIN_TOKEN, 1).await;
    let settings = fx.settings(&[]);
    let chain = fx.chain(&settings);
    let store = OwnStore::production(&settings);
    save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;

    let report = sign_out_own_session(settings.api_base_url.as_deref(), &store, &chain).await;

    assert_eq!(report.found, [StoreKind::File]);
    assert_eq!(report.revoked, [vec![StoreKind::File]]);
    assert_eq!(report.removed, [StoreKind::File]);
    assert!(report.ok());
    assert!(!fx.own_file().exists());
    assert_eq!(report.next_source, None);
    assert_eq!(targets_of(&fx.mock).await, ["POST /2.2/logout"]);
    Ok(())
}

#[tokio::test]
async fn a_token_another_source_holds_is_deleted_locally_without_signing_out() -> anyhow::Result<()>
{
    // eeroctl's file, the environment token and the explicit file in turn.
    for holder in ["eeroctl file", "environment token", "explicit file"] {
        let fx = Fixture::new().await;
        let explicit = fx.dir.path().join("explicit.json");
        let extra: Vec<(&str, String)> = match holder {
            "environment token" => vec![("RUSTEERO_SESSION_TOKEN", LOGIN_TOKEN.to_owned())],
            "explicit file" => vec![(
                "EERO_MCP_SESSION_FILE",
                explicit.to_str().expect("utf-8").to_owned(),
            )],
            _ => vec![],
        };
        let extra_refs: Vec<(&str, &str)> = extra.iter().map(|(a, b)| (*a, b.as_str())).collect();
        let settings = fx.settings(&extra_refs);
        let chain = fx.chain(&settings);
        let store = OwnStore::production(&settings);

        // The own file and the other source hold the very same session.
        let shared = record(LOGIN_TOKEN);
        std::fs::create_dir_all(fx.own_dir())?;
        std::fs::write(fx.own_file(), &shared)?;
        match holder {
            "eeroctl file" => {
                std::fs::create_dir_all(fx.eeroctl_file().parent().expect("parent"))?;
                std::fs::write(fx.eeroctl_file(), &shared)?;
            }
            "explicit file" => std::fs::write(&explicit, &shared)?,
            _ => {}
        }

        let report = sign_out_own_session(settings.api_base_url.as_deref(), &store, &chain).await;

        assert!(report.revoked.is_empty(), "{holder}: no sign-out request");
        assert_eq!(report.held_elsewhere.len(), 1, "{holder}");
        let source = match holder {
            "eeroctl file" => Source::EeroctlFile,
            "environment token" => Source::EnvToken,
            _ => Source::ExplicitFile,
        };
        assert_eq!(report.held_elsewhere[0].sources, [source], "{holder}");
        assert_eq!(
            report.removed,
            [StoreKind::File],
            "{holder}: still deleted locally"
        );
        assert!(!fx.own_file().exists(), "{holder}");
        assert!(targets_of(&fx.mock).await.is_empty(), "{holder}");
        // The other copy is untouched, byte for byte.
        match holder {
            "eeroctl file" => assert_eq!(read(&fx.eeroctl_file()), shared),
            "explicit file" => assert_eq!(read(&explicit), shared),
            _ => {}
        }
        assert_eq!(report.next_source, Some(source), "{holder}");
    }
    Ok(())
}

#[tokio::test]
async fn logout_names_the_stores_it_could_not_check() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    // An explicit file that is a directory cannot be read, so a copy there cannot be ruled out;
    // the keyring is switched off.
    let unreadable = fx.dir.path().join("a-directory");
    std::fs::create_dir_all(&unreadable)?;
    let settings = fx.settings(&[]);
    let chain = fx.chain(&settings);
    let store = OwnStore::production(&settings);
    mount_logout(&fx.mock, LOGIN_TOKEN, 1).await;
    save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;

    // Re-create the chain with the unreadable explicit file.
    let settings = fx.settings(&[("EERO_MCP_SESSION_FILE", unreadable.to_str().expect("utf-8"))]);
    let chain = fx.chain(&settings);
    let report = sign_out_own_session(settings.api_base_url.as_deref(), &store, &chain).await;

    assert!(
        report.not_checked.contains(&NotChecked::Keyring),
        "{:?}",
        report.not_checked
    );
    assert!(
        report
            .not_checked
            .contains(&NotChecked::Source(Source::ExplicitFile)),
        "{:?}",
        report.not_checked
    );
    // Not being able to rule out a copy does not stop the sign-out and the deletion.
    assert_eq!(report.revoked.len(), 1);
    assert_eq!(report.removed, [StoreKind::File]);
    // The shared keyring is switched off, never read: it is not a read error.
    assert!(
        !report
            .not_checked
            .contains(&NotChecked::Source(Source::SharedKeyring)),
        "{:?}",
        report.not_checked
    );
    Ok(())
}

/// Stores a session in the own file, then signs it out; the shared sources hold nothing.
async fn log_out_a_file_session(
    fx: &Fixture,
    settings: &Settings,
) -> anyhow::Result<eero_mcp::auth::LogoutReport> {
    let chain = fx.chain(settings);
    let store = OwnStore::production(settings);
    mount_logout(&fx.mock, LOGIN_TOKEN, 1).await;
    std::fs::create_dir_all(fx.own_dir())?;
    std::fs::write(fx.own_file(), record(LOGIN_TOKEN))?;

    let report = sign_out_own_session(settings.api_base_url.as_deref(), &store, &chain).await;

    assert_eq!(report.revoked.len(), 1, "{report:?}");
    assert_eq!(report.removed, [StoreKind::File]);
    assert_eq!(targets_of(&fx.mock).await, ["POST /2.2/logout"]);
    Ok(report)
}

#[tokio::test]
async fn a_switched_off_keyring_is_not_reported_as_an_unreadable_shared_keyring()
-> anyhow::Result<()> {
    // EERO_MCP_NO_KEYRING=1: in the default build the keyring is switched off, in the headless
    // build it does not exist. Either way nothing tries to read the shared eero-api entry.
    let fx = Fixture::new().await;
    let settings = fx.settings(&[]);
    assert!(!fx.chain(&settings).keyring_active());

    let report = log_out_a_file_session(&fx, &settings).await?;

    // Only eero-mcp's own entry is named (an earlier record may survive there); the shared entry
    // was never read, so nothing is claimed about it.
    assert_eq!(report.not_checked, [NotChecked::Keyring]);
    Ok(())
}

// The headless build with the keyring switch left on: the keyring cannot be read because it is not
// compiled in, which is the same as switched off.
#[cfg(not(feature = "keyring"))]
#[tokio::test]
async fn a_headless_build_never_claims_the_shared_keyring_was_unreadable() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    let settings = fx.settings_with_keyring(true, &[]);
    assert!(!fx.chain(&settings).keyring_active());

    let report = log_out_a_file_session(&fx, &settings).await?;

    assert_eq!(report.not_checked, [NotChecked::Keyring]);
    Ok(())
}

// Unix only: Windows reports a path through a regular file as not found, so the record reads as
// absent there rather than unreadable.
#[cfg(unix)]
#[tokio::test]
async fn a_record_that_cannot_be_deleted_fails_the_logout() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    // The own directory is a regular file: the own file's path cannot be read or removed.
    let blocked = fx.dir.path().join("blocked");
    std::fs::write(&blocked, "not a directory")?;
    let settings = fx.settings(&[("EERO_MCP_CONFIG_DIR", blocked.to_str().expect("utf-8"))]);
    let chain = fx.chain(&settings);

    let report = sign_out_own_session(
        settings.api_base_url.as_deref(),
        &OwnStore::production(&settings),
        &chain,
    )
    .await;

    assert_eq!(
        report.found,
        [StoreKind::File],
        "an unreadable record still counts"
    );
    assert_eq!(report.delete_failed, [StoreKind::File]);
    assert!(!report.ok());
    assert!(
        targets_of(&fx.mock).await.is_empty(),
        "no usable session, no sign-out"
    );
    Ok(())
}

#[tokio::test]
async fn revoking_sends_one_sign_out_through_a_client_holding_only_that_session()
-> anyhow::Result<()> {
    let fx = Fixture::new().await;
    mount_logout(&fx.mock, LOGIN_TOKEN, 1).await;
    assert!(revoke_session(Some(&fx.origin()), &token(LOGIN_TOKEN)).await);
    assert_eq!(targets_of(&fx.mock).await, ["POST /2.2/logout"]);
    Ok(())
}

// ===================== the keyring stand-in =====================
//
// Keyring builds only: the stand-in keyring is read by the credential chain, which consults a
// keyring only when the feature is compiled in.

#[cfg(feature = "keyring")]
mod with_keyring {
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    use eero_mcp::credentials::{FileRead, KeyringEntry, KeyringRead, Sources};
    use rusteero::{CredentialStore, MemoryStore, Session, StorageError};

    use super::*;

    /// A fake keyring source over rusteero's in-memory store, so the read-back sees what was saved.
    struct StandIn {
        keyring: Arc<MemoryStore>,
    }

    impl Sources for StandIn {
        fn keyring_record(&self, entry: KeyringEntry) -> KeyringRead {
            match entry {
                KeyringEntry::Shared => KeyringRead::Missing,
                KeyringEntry::Own => match self.keyring.load() {
                    Ok(session) if session.is_valid() => {
                        KeyringRead::record(record(session.token().expose_secret()))
                    }
                    _ => KeyringRead::Missing,
                },
            }
        }

        fn read_file(&self, path: &Path) -> FileRead {
            SystemSources.read_file(path)
        }
    }

    /// A keyring whose writes fail, and whose clear can be made to fail too. It holds an older
    /// record, which the fake source reads.
    #[derive(Debug)]
    struct BrokenKeyring {
        older: Mutex<Option<String>>,
        clear_works: bool,
    }

    impl CredentialStore for BrokenKeyring {
        fn load(&self) -> Result<Session, StorageError> {
            Ok(Session::empty())
        }

        fn save(&self, _session: &Session) -> Result<(), StorageError> {
            Err(StorageError::Backend {
                backend: "keyring".to_owned(),
                message: "simulated failure".to_owned(),
            })
        }

        fn clear(&self) -> Result<(), StorageError> {
            if self.clear_works {
                *self.older.lock().expect("lock") = None;
                Ok(())
            } else {
                Err(StorageError::Backend {
                    backend: "keyring".to_owned(),
                    message: "simulated failure".to_owned(),
                })
            }
        }
    }

    /// A source that reads the older record `BrokenKeyring` still holds.
    struct OlderRecord(Arc<BrokenKeyring>);

    impl Sources for OlderRecord {
        fn keyring_record(&self, entry: KeyringEntry) -> KeyringRead {
            match (entry, self.0.older.lock().expect("lock").as_deref()) {
                (KeyringEntry::Own, Some(older)) => KeyringRead::record(record(older)),
                (KeyringEntry::Own, None) | (KeyringEntry::Shared, _) => KeyringRead::Missing,
            }
        }

        fn read_file(&self, path: &Path) -> FileRead {
            SystemSources.read_file(path)
        }
    }

    fn stand_in_chain(
        fx: &Fixture,
        keyring: &Arc<MemoryStore>,
    ) -> (Settings, Arc<CredentialChain>) {
        let settings = fx.settings_with_keyring(true, &[]);
        let chain = Arc::new(CredentialChain::new(
            &settings,
            Arc::new(StandIn {
                keyring: Arc::clone(keyring),
            }),
        ));
        (settings, chain)
    }

    #[tokio::test]
    async fn a_working_keyring_holds_the_session_and_the_file_stays_empty() -> anyhow::Result<()> {
        let fx = Fixture::new().await;
        let keyring = Arc::new(MemoryStore::new());
        let (settings, chain) = stand_in_chain(&fx, &keyring);
        let store = OwnStore::with_backends(
            Some(Arc::clone(&keyring) as Arc<dyn CredentialStore>),
            settings.own_file.clone(),
        );

        let saved = save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;

        assert_eq!(saved.kind, StoreKind::Keyring);
        assert!(!fx.own_file().exists(), "the file is only the fallback");
        let resolved = chain.startup_resolved().expect("ok").expect("a hit");
        assert_eq!(resolved.source, Source::OwnKeyring);
        Ok(())
    }

    #[tokio::test]
    async fn a_leftover_file_record_is_removed_after_a_keyring_save() -> anyhow::Result<()> {
        let fx = Fixture::new().await;
        let keyring = Arc::new(MemoryStore::new());
        let (settings, chain) = stand_in_chain(&fx, &keyring);
        let store = OwnStore::with_backends(
            Some(Arc::clone(&keyring) as Arc<dyn CredentialStore>),
            settings.own_file.clone(),
        );
        // An earlier login that fell back to the file.
        std::fs::create_dir_all(fx.own_dir())?;
        std::fs::write(fx.own_file(), record("older-session"))?;

        let saved = save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;

        assert_eq!(saved.kind, StoreKind::Keyring);
        assert!(
            !fx.own_file().exists(),
            "the leftover record of the earlier login is removed"
        );
        assert_eq!(
            chain.own_store_token().expect("a token").expose_secret(),
            LOGIN_TOKEN
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failing_keyring_falls_back_to_the_file() -> anyhow::Result<()> {
        let fx = Fixture::new().await;
        let broken = Arc::new(BrokenKeyring {
            older: Mutex::new(None),
            clear_works: true,
        });
        let settings = fx.settings_with_keyring(true, &[]);
        let chain = Arc::new(CredentialChain::new(
            &settings,
            Arc::new(OlderRecord(Arc::clone(&broken))),
        ));
        let store = OwnStore::with_backends(
            Some(Arc::clone(&broken) as Arc<dyn CredentialStore>),
            settings.own_file.clone(),
        );

        let saved = save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;

        assert_eq!(saved.kind, StoreKind::File);
        assert!(read(&fx.own_file()).contains(LOGIN_TOKEN));
        Ok(())
    }

    #[tokio::test]
    async fn an_older_keyring_record_is_cleared_when_the_file_takes_over() -> anyhow::Result<()> {
        let fx = Fixture::new().await;
        let broken = Arc::new(BrokenKeyring {
            older: Mutex::new(Some("older-session".to_owned())),
            clear_works: true,
        });
        let settings = fx.settings_with_keyring(true, &[]);
        let chain = Arc::new(CredentialChain::new(
            &settings,
            Arc::new(OlderRecord(Arc::clone(&broken))),
        ));
        let store = OwnStore::with_backends(
            Some(Arc::clone(&broken) as Arc<dyn CredentialStore>),
            settings.own_file.clone(),
        );

        // The keyring read still shows the older record, which would win; the save clears it.
        let saved = save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;

        assert_eq!(saved.kind, StoreKind::File);
        assert_eq!(broken.older.lock().expect("lock").as_deref(), None);
        assert_eq!(
            chain.own_store_token().expect("a token").expose_secret(),
            LOGIN_TOKEN
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_older_keyring_record_that_cannot_be_cleared_shadows_the_save() -> anyhow::Result<()>
    {
        let fx = Fixture::new().await;
        let broken = Arc::new(BrokenKeyring {
            older: Mutex::new(Some("older-session".to_owned())),
            clear_works: false,
        });
        let settings = fx.settings_with_keyring(true, &[]);
        let chain = Arc::new(CredentialChain::new(
            &settings,
            Arc::new(OlderRecord(Arc::clone(&broken))),
        ));
        let store = OwnStore::with_backends(
            Some(Arc::clone(&broken) as Arc<dyn CredentialStore>),
            settings.own_file.clone(),
        );

        // The file holds the new token, but the unreachable older keyring record still resolves
        // first: the save counts as failed.
        let error = save_session(&store, &chain, &token(LOGIN_TOKEN))
            .await
            .expect_err("shadowed");
        assert_eq!(error, SaveError::Shadowed);

        // A failed save means nothing was stored: the record the save wrote is removed again, so
        // it cannot resurface (revoked, and unused) when the older keyring record goes away. The
        // older record itself is untouched.
        assert!(
            !fx.own_file().exists(),
            "the new session is not left in the file"
        );
        assert_eq!(
            broken.older.lock().expect("lock").as_deref(),
            Some("older-session")
        );
        assert_eq!(
            chain.own_store_token().expect("a token").expose_secret(),
            "older-session"
        );
        Ok(())
    }

    #[tokio::test]
    async fn logging_in_again_replaces_the_keyring_and_the_file_session_and_signs_both_out()
    -> anyhow::Result<()> {
        let fx = Fixture::new().await;
        mount_logout(&fx.mock, "older-keyring-session", 1).await;
        mount_logout(&fx.mock, "older-file-session", 1).await;
        let keyring = Arc::new(MemoryStore::new());
        let (settings, chain) = stand_in_chain(&fx, &keyring);
        let store = OwnStore::with_backends(
            Some(Arc::clone(&keyring) as Arc<dyn CredentialStore>),
            settings.own_file.clone(),
        );
        keyring.save(&Session::from_token("older-keyring-session"))?;
        std::fs::create_dir_all(fx.own_dir())?;
        std::fs::write(fx.own_file(), record("older-file-session"))?;

        let saved = save_session(&store, &chain, &token(LOGIN_TOKEN)).await?;

        assert_eq!(saved.kind, StoreKind::Keyring);
        assert_eq!(saved.replaced_count(), 2);
        assert!(!fx.own_file().exists());
        let outcome = revoke_replaced(settings.api_base_url.as_deref(), &chain, saved).await;
        assert_eq!(
            (outcome.revoked, outcome.held_elsewhere, outcome.not_sent),
            (2, 0, 0)
        );
        let mut sent = targets_of(&fx.mock).await;
        sent.dedup();
        assert_eq!(sent, ["POST /2.2/logout"]);
        assert_eq!(targets_of(&fx.mock).await.len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_save_replaces_nothing_and_signs_nothing_out() -> anyhow::Result<()> {
        let fx = Fixture::new().await;
        let broken = Arc::new(BrokenKeyring {
            older: Mutex::new(Some("older-session".to_owned())),
            clear_works: false,
        });
        let settings = fx.settings_with_keyring(true, &[]);
        let chain = Arc::new(CredentialChain::new(
            &settings,
            Arc::new(OlderRecord(Arc::clone(&broken))),
        ));
        let store = OwnStore::with_backends(
            Some(Arc::clone(&broken) as Arc<dyn CredentialStore>),
            settings.own_file.clone(),
        );

        // Shadowed: the save fails, so there is no `Saved` to revoke anything from, and the older
        // session is still the stored one.
        assert!(
            save_session(&store, &chain, &token(LOGIN_TOKEN))
                .await
                .is_err()
        );
        assert!(targets_of(&fx.mock).await.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn logout_signs_out_each_distinct_session_of_the_keyring_and_the_file()
    -> anyhow::Result<()> {
        let fx = Fixture::new().await;
        mount_logout(&fx.mock, LOGIN_TOKEN, 1).await;
        mount_logout(&fx.mock, LOGIN_TOKEN_2, 1).await;
        let keyring = Arc::new(MemoryStore::new());
        let (settings, chain) = stand_in_chain(&fx, &keyring);
        let store = OwnStore::with_backends(
            Some(Arc::clone(&keyring) as Arc<dyn CredentialStore>),
            settings.own_file.clone(),
        );
        keyring.save(&Session::from_token(LOGIN_TOKEN))?;
        std::fs::create_dir_all(fx.own_dir())?;
        std::fs::write(fx.own_file(), record(LOGIN_TOKEN_2))?;

        let report = sign_out_own_session(settings.api_base_url.as_deref(), &store, &chain).await;

        assert_eq!(report.found, [StoreKind::Keyring, StoreKind::File]);
        assert_eq!(report.revoked.len(), 2);
        assert_eq!(report.removed, [StoreKind::Keyring, StoreKind::File]);
        assert!(report.ok());
        assert!(!fx.own_file().exists());
        assert!(!keyring.load()?.is_valid());
        Ok(())
    }

    /// A keyring that cannot be reached (no Secret Service, a locked keychain): every read fails.
    struct Unreachable;

    impl Sources for Unreachable {
        fn keyring_record(&self, _entry: KeyringEntry) -> KeyringRead {
            KeyringRead::Unavailable
        }

        fn read_file(&self, path: &Path) -> FileRead {
            SystemSources.read_file(path)
        }
    }

    #[tokio::test]
    async fn an_enabled_keyring_that_cannot_be_read_is_reported_as_not_checked()
    -> anyhow::Result<()> {
        let fx = Fixture::new().await;
        mount_logout(&fx.mock, LOGIN_TOKEN, 1).await;
        let settings = fx.settings_with_keyring(true, &[]);
        let chain = Arc::new(CredentialChain::new(&settings, Arc::new(Unreachable)));
        assert!(chain.keyring_active());
        let store = OwnStore::with_backends(None, settings.own_file.clone());
        std::fs::create_dir_all(fx.own_dir())?;
        std::fs::write(fx.own_file(), record(LOGIN_TOKEN))?;

        let report = sign_out_own_session(settings.api_base_url.as_deref(), &store, &chain).await;

        // A real read error: both keyring entries are named, because a copy of the session cannot
        // be ruled out there. It does not stop the sign-out or the deletion.
        assert!(
            report.not_checked.contains(&NotChecked::Keyring),
            "{:?}",
            report.not_checked
        );
        assert!(
            report
                .not_checked
                .contains(&NotChecked::Source(Source::SharedKeyring)),
            "{:?}",
            report.not_checked
        );
        assert_eq!(report.revoked.len(), 1);
        assert_eq!(report.removed, [StoreKind::File]);
        Ok(())
    }

    #[tokio::test]
    async fn an_enabled_keyring_that_can_be_read_leaves_nothing_unchecked() -> anyhow::Result<()> {
        let fx = Fixture::new().await;
        mount_logout(&fx.mock, LOGIN_TOKEN, 1).await;
        let keyring = Arc::new(MemoryStore::new());
        let (settings, chain) = stand_in_chain(&fx, &keyring);
        let store = OwnStore::with_backends(
            Some(Arc::clone(&keyring) as Arc<dyn CredentialStore>),
            settings.own_file.clone(),
        );
        std::fs::create_dir_all(fx.own_dir())?;
        std::fs::write(fx.own_file(), record(LOGIN_TOKEN))?;

        let report = sign_out_own_session(settings.api_base_url.as_deref(), &store, &chain).await;

        // Both keyring entries were read (found empty): nothing to report.
        assert!(report.not_checked.is_empty(), "{:?}", report.not_checked);
        assert_eq!(report.revoked.len(), 1);
        assert_eq!(report.removed, [StoreKind::File]);
        Ok(())
    }

    #[tokio::test]
    async fn a_session_held_in_both_backends_is_signed_out_once() -> anyhow::Result<()> {
        let fx = Fixture::new().await;
        mount_logout(&fx.mock, LOGIN_TOKEN, 1).await;
        let keyring = Arc::new(MemoryStore::new());
        let (settings, chain) = stand_in_chain(&fx, &keyring);
        let store = OwnStore::with_backends(
            Some(Arc::clone(&keyring) as Arc<dyn CredentialStore>),
            settings.own_file.clone(),
        );
        keyring.save(&Session::from_token(LOGIN_TOKEN))?;
        std::fs::create_dir_all(fx.own_dir())?;
        std::fs::write(fx.own_file(), record(LOGIN_TOKEN))?;

        let report = sign_out_own_session(settings.api_base_url.as_deref(), &store, &chain).await;

        assert_eq!(report.revoked, [vec![StoreKind::Keyring, StoreKind::File]]);
        assert_eq!(report.removed.len(), 2);
        assert_eq!(targets_of(&fx.mock).await, ["POST /2.2/logout"]);
        Ok(())
    }
}

// ===================== the front ends refuse before any request =====================

/// Lines from a script.
struct Lines(VecDeque<Line>);

impl Lines {
    fn new(lines: &[&str]) -> Self {
        Self(lines.iter().map(|l| Line::Text((*l).to_owned())).collect())
    }
}

impl LineSource for Lines {
    fn next_line(&mut self) -> Line {
        self.0.pop_front().unwrap_or(Line::End)
    }
}

#[tokio::test]
async fn login_and_logout_refuse_when_the_explicit_file_is_the_own_file() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    let own = fx.own_file();
    std::fs::create_dir_all(fx.own_dir())?;
    let original = record("explicitly-configured");
    std::fs::write(&own, &original)?;
    let settings = fx.settings(&[("EERO_MCP_SESSION_FILE", own.to_str().expect("utf-8"))]);
    let chain = fx.chain(&settings);

    assert_eq!(
        cli::run_login_command(&settings, &chain, Lines::new(&[IDENTIFIER, CODE])).await,
        1
    );
    assert_eq!(cli::run_logout_command(&settings, &chain).await, 1);

    assert_eq!(read(&own), original, "nothing was written or deleted");
    assert!(targets_of(&fx.mock).await.is_empty(), "nothing was sent");
    Ok(())
}

#[cfg(unix)]
#[tokio::test]
async fn the_refusal_also_sees_through_a_symlink() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    std::fs::create_dir_all(fx.own_dir())?;
    std::fs::write(fx.own_file(), record("explicitly-configured"))?;
    let link = fx.dir.path().join("link.json");
    std::os::unix::fs::symlink(fx.own_file(), &link)?;
    let settings = fx.settings(&[("EERO_MCP_SESSION_FILE", link.to_str().expect("utf-8"))]);
    let chain = fx.chain(&settings);

    assert_eq!(cli::run_logout_command(&settings, &chain).await, 1);
    assert_eq!(
        cli::run_login_command(&settings, &chain, Lines::new(&[IDENTIFIER, CODE])).await,
        1
    );
    assert!(fx.own_file().exists());
    assert!(targets_of(&fx.mock).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_terminal_login_with_nowhere_to_store_the_session_is_refused_before_any_request()
-> anyhow::Result<()> {
    let fx = Fixture::new().await;
    let settings = Settings::from_env_for(
        &EnvMap::from_pairs([
            ("EERO_MCP_NO_KEYRING", "1".to_owned()),
            ("EERO_MCP_API_BASE_URL", fx.origin()),
        ]),
        false,
    )?;
    let chain = Arc::new(CredentialChain::new(&settings, Arc::new(SystemSources)));

    assert_eq!(
        cli::run_login_command(&settings, &chain, Lines::new(&[IDENTIFIER, CODE])).await,
        1
    );
    assert!(
        targets_of(&fx.mock).await.is_empty(),
        "no message was triggered"
    );
    Ok(())
}

#[tokio::test]
async fn a_terminal_login_saves_the_session_and_a_failed_save_signs_it_out_again()
-> anyhow::Result<()> {
    // Success: scripted lines, the own file holds the session.
    let fx = Fixture::new().await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 1).await;
    let settings = fx.settings(&[]);
    let chain = fx.chain(&settings);
    assert_eq!(
        cli::run_login_command(&settings, &chain, Lines::new(&[IDENTIFIER, CODE])).await,
        0
    );
    assert!(read(&fx.own_file()).contains(LOGIN_TOKEN));

    // A save that cannot land revokes the new session and fails.
    let failing = Fixture::new().await;
    let blocked = failing.dir.path().join("blocked");
    std::fs::write(&blocked, "not a directory")?;
    mount_start(&failing.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&failing.mock, LOGIN_TOKEN, CODE, 1).await;
    mount_logout(&failing.mock, LOGIN_TOKEN, 1).await;
    let settings = failing.settings(&[("EERO_MCP_CONFIG_DIR", blocked.to_str().expect("utf-8"))]);
    let chain = failing.chain(&settings);
    assert_eq!(
        cli::run_login_command(&settings, &chain, Lines::new(&[IDENTIFIER, CODE])).await,
        1
    );
    assert_eq!(
        targets_of(&failing.mock).await,
        [
            "POST /2.2/login",
            "POST /2.2/login/verify",
            "POST /2.2/logout"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_second_terminal_login_signs_the_first_session_out() -> anyhow::Result<()> {
    let fx = Fixture::new().await;
    // Two logins, each with its own login token; the first session is signed out after the second
    // is stored.
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN, CODE, 1).await;
    mount_start(&fx.mock, IDENTIFIER, LOGIN_TOKEN_2, 1).await;
    mount_verify_ok(&fx.mock, LOGIN_TOKEN_2, CODE_2, 1).await;
    mount_logout(&fx.mock, LOGIN_TOKEN, 1).await;
    let settings = fx.settings(&[]);
    let chain = fx.chain(&settings);

    assert_eq!(
        cli::run_login_command(&settings, &chain, Lines::new(&[IDENTIFIER, CODE])).await,
        0
    );
    assert_eq!(
        targets_of(&fx.mock).await.len(),
        2,
        "the first login signs nothing out"
    );
    assert_eq!(
        cli::run_login_command(&settings, &chain, Lines::new(&[IDENTIFIER, CODE_2])).await,
        0
    );

    assert_eq!(
        targets_of(&fx.mock).await,
        [
            "POST /2.2/login",
            "POST /2.2/login/verify",
            "POST /2.2/login",
            "POST /2.2/login/verify",
            "POST /2.2/logout"
        ]
    );
    let stored = read(&fx.own_file());
    assert!(
        stored.contains(LOGIN_TOKEN_2) && !stored.contains(LOGIN_TOKEN),
        "{stored}"
    );
    Ok(())
}
