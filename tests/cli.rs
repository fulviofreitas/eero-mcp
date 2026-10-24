//! The `login`, `logout` and `status` subcommands through the built binary, against the mock eero
//! cloud, with scripted stdin.
//!
//! The child runs in a cleared environment: only `PATH` survives (and `SystemRoot` on Windows),
//! `HOME`, `APPDATA`, `XDG_CONFIG_HOME`, `EEROCTL_CONFIG_DIR` and `EERO_MCP_CONFIG_DIR` point into
//! a per-test temporary directory, `EERO_MCP_NO_KEYRING` is 1 (so no child, on any platform,
//! touches the real keyring) and `EERO_MCP_API_BASE_URL` points at the mock. The subcommand tests
//! pass no token unless the test is about one, so the sandbox is what keeps them away from the
//! developer's credentials. Every login and logout POST a test expects is mounted above the write
//! tripwire with a pinned count.
//!
//! Prompts go to stderr and results to stdout; neither stream may ever carry the identifier, the
//! code or a token.

mod common;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use common::{
    CODE, CODE_2, IDENTIFIER, LOGIN_TOKEN, LOGIN_TOKEN_2, authed_get_as, fixture, json_response,
    mock_cloud, mount_logout, mount_resend, mount_start, mount_start_error, mount_verify_error,
    mount_verify_ok, targets_of,
};
use tempfile::TempDir;
use wiremock::{MockServer, ResponseTemplate};

/// A per-test sandbox: the temporary directory every environment path points into.
struct Sandbox {
    dir: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// eero-mcp's own directory and file.
    fn own_dir(&self) -> PathBuf {
        self.path("cfg")
    }

    fn own_file(&self) -> PathBuf {
        self.own_dir().join("session.json")
    }

    /// eeroctl's default credential file.
    fn eeroctl_file(&self) -> PathBuf {
        self.path("eeroctl").join("cookies.json")
    }
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

impl Run {
    /// Neither stream carries a secret.
    fn assert_clean(&self) {
        for stream in [&self.stdout, &self.stderr] {
            for secret in [
                IDENTIFIER,
                CODE,
                CODE_2,
                LOGIN_TOKEN,
                LOGIN_TOKEN_2,
                "status-token-0001",
            ] {
                assert!(!stream.contains(secret), "{secret} leaked:\n{stream}");
            }
        }
    }
}

/// A command in the sandboxed environment. Extra variables go on the returned `Command`.
fn command(sandbox: &Sandbox, origin: &str, subcommand: &str) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_eero-mcp"));
    command
        .arg(subcommand)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", sandbox.path("home"))
        .env("APPDATA", sandbox.path("appdata"))
        .env("XDG_CONFIG_HOME", sandbox.path("xdg"))
        .env("EEROCTL_CONFIG_DIR", sandbox.path("eeroctl"))
        .env("EERO_MCP_CONFIG_DIR", sandbox.own_dir())
        .env("EERO_MCP_NO_KEYRING", "1")
        .env("EERO_MCP_API_BASE_URL", origin);
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    command
}

/// Runs the command with `stdin` as its input, then closes stdin.
async fn run(mut command: Command, stdin: &'static str) -> Run {
    tokio::task::spawn_blocking(move || {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary starts");
        {
            let mut input = child.stdin.take().expect("stdin is piped");
            input.write_all(stdin.as_bytes()).expect("write stdin");
        }
        let output = child.wait_with_output().expect("the binary ends");
        Run {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    })
    .await
    .expect("the runner thread")
}

fn record(token: &str) -> String {
    format!(r#"{{"session_id":"{token}","schema_version":2}}"#)
}

async fn login_succeeds(mock: &MockServer) {
    mount_start(mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(mock, LOGIN_TOKEN, CODE, 1).await;
}

// ===================== login =====================

#[tokio::test]
async fn login_saves_the_session_to_the_own_file_and_says_where() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    login_succeeds(&mock).await;

    let run = run(
        command(&sandbox, &mock.uri(), "login"),
        "user@example.com\n000001\n",
    )
    .await;

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    // The result is on stdout and names the own file; the prompts are on stderr.
    assert!(run.stdout.contains("Logged in"), "{}", run.stdout);
    assert!(
        run.stdout
            .contains(sandbox.own_file().to_str().expect("utf-8")),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("without a restart"), "{}", run.stdout);
    assert!(
        run.stderr.contains("Email address or phone number"),
        "{}",
        run.stderr
    );
    assert!(run.stderr.contains("one-time code"), "{}", run.stderr);
    run.assert_clean();

    // The file holds the eero-api record, and on Unix is private.
    let saved: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(sandbox.own_file())?)?;
    assert_eq!(saved["session_id"], LOGIN_TOKEN);
    assert_eq!(saved["schema_version"], 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |path: &std::path::Path| {
            std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777
        };
        assert_eq!(mode(&sandbox.own_file()), 0o600);
        assert_eq!(mode(&sandbox.own_dir()), 0o700);
    }
    assert_eq!(
        targets_of(&mock).await,
        ["POST /2.2/login", "POST /2.2/login/verify"]
    );
    Ok(())
}

#[tokio::test]
async fn an_empty_line_and_new_resend_the_code() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    mount_start(&mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_resend(&mock, LOGIN_TOKEN, 2).await;
    mount_verify_ok(&mock, LOGIN_TOKEN, CODE, 1).await;

    let run = run(
        command(&sandbox, &mock.uri(), "login"),
        "user@example.com\n\nnew\n000001\n",
    )
    .await;

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    run.assert_clean();
    assert_eq!(
        targets_of(&mock).await,
        [
            "POST /2.2/login",
            "POST /2.2/login/resend",
            "POST /2.2/login/resend",
            "POST /2.2/login/verify"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_rejected_code_starts_again_and_the_second_code_is_accepted() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    mount_start(&mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_start(&mock, IDENTIFIER, LOGIN_TOKEN_2, 1).await;
    mount_verify_error(
        &mock,
        LOGIN_TOKEN,
        CODE,
        401,
        Some("error.verification.invalid"),
        1,
    )
    .await;
    mount_verify_ok(&mock, LOGIN_TOKEN_2, CODE_2, 1).await;

    let run = run(
        command(&sandbox, &mock.uri(), "login"),
        "user@example.com\n000001\n000002\n",
    )
    .await;

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(run.stderr.contains("not accepted"), "{}", run.stderr);
    run.assert_clean();
    assert!(std::fs::read_to_string(sandbox.own_file())?.contains(LOGIN_TOKEN_2));
    Ok(())
}

#[tokio::test]
async fn three_rejected_codes_exit_one() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    mount_start(&mock, IDENTIFIER, LOGIN_TOKEN, 3).await;
    mount_verify_error(
        &mock,
        LOGIN_TOKEN,
        CODE,
        401,
        Some("error.verification.invalid"),
        3,
    )
    .await;

    let run = run(
        command(&sandbox, &mock.uri(), "login"),
        "user@example.com\n000001\n000001\n000001\n",
    )
    .await;

    assert_eq!(run.code, Some(1));
    assert!(run.stderr.contains("3 attempts"), "{}", run.stderr);
    run.assert_clean();
    assert!(!sandbox.own_file().exists());
    Ok(())
}

#[tokio::test]
async fn a_blocked_verification_exits_one_after_a_single_start() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    mount_start(&mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_error(
        &mock,
        LOGIN_TOKEN,
        CODE,
        401,
        Some("error.verification.blocked"),
        1,
    )
    .await;

    let run = run(
        command(&sandbox, &mock.uri(), "login"),
        "user@example.com\n000001\n000001\n",
    )
    .await;

    assert_eq!(run.code, Some(1));
    assert!(
        run.stderr.contains("refused the verification"),
        "{}",
        run.stderr
    );
    run.assert_clean();
    assert!(!sandbox.own_file().exists());
    Ok(())
}

#[tokio::test]
async fn a_refused_start_exits_one_with_the_amazon_hint() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    mount_start_error(&mock, IDENTIFIER, 400, "error.user.amazon_login.exists", 1).await;

    let run = run(
        command(&sandbox, &mock.uri(), "login"),
        "user@example.com\n",
    )
    .await;

    assert_eq!(run.code, Some(1));
    assert!(run.stderr.contains("Amazon"), "{}", run.stderr);
    run.assert_clean();
    Ok(())
}

#[tokio::test]
async fn an_invalid_identifier_is_asked_for_again_and_three_in_a_row_exit_one() -> anyhow::Result<()>
{
    // Two bad entries (empty, and a line over 1 KiB), then a good one.
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    login_succeeds(&mock).await;
    let long_line: &'static str = Box::leak(format!("{}\n", "x".repeat(2048)).into_boxed_str());
    let input: &'static str =
        Box::leak(format!("\n{long_line}user@example.com\n000001\n").into_boxed_str());
    let ok = run(command(&sandbox, &mock.uri(), "login"), input).await;
    assert_eq!(ok.code, Some(0), "{}", ok.stderr);
    assert_eq!(
        ok.stderr
            .matches("does not look like an email address")
            .count(),
        2,
        "{}",
        ok.stderr
    );

    // Three in a row end the login without a request.
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    let run = run(command(&sandbox, &mock.uri(), "login"), "\n\n   \n").await;
    assert_eq!(run.code, Some(1));
    assert!(
        run.stderr.contains("No valid email address"),
        "{}",
        run.stderr
    );
    assert!(targets_of(&mock).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn closed_stdin_exits_one_before_and_after_the_start() -> anyhow::Result<()> {
    // Before anything is asked.
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    let run_a = run(command(&sandbox, &mock.uri(), "login"), "").await;
    assert_eq!(run_a.code, Some(1));
    assert!(run_a.stderr.contains("input ended"), "{}", run_a.stderr);
    assert!(targets_of(&mock).await.is_empty());

    // After the start: the code never comes.
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    mount_start(&mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    let run_b = run(
        command(&sandbox, &mock.uri(), "login"),
        "user@example.com\n",
    )
    .await;
    assert_eq!(run_b.code, Some(1));
    run_b.assert_clean();
    assert!(!sandbox.own_file().exists());
    Ok(())
}

#[tokio::test]
async fn a_failed_save_signs_the_new_session_out_and_exits_one() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    // The own directory is a regular file, so the session cannot be saved.
    std::fs::write(sandbox.own_dir(), "not a directory")?;
    login_succeeds(&mock).await;
    mount_logout(&mock, LOGIN_TOKEN, 1).await;

    let run = run(
        command(&sandbox, &mock.uri(), "login"),
        "user@example.com\n000001\n",
    )
    .await;

    assert_eq!(run.code, Some(1));
    assert!(run.stderr.contains("could not be saved"), "{}", run.stderr);
    assert!(run.stderr.contains("signed out"), "{}", run.stderr);
    run.assert_clean();
    assert_eq!(
        targets_of(&mock).await,
        [
            "POST /2.2/login",
            "POST /2.2/login/verify",
            "POST /2.2/logout"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn an_explicit_file_that_is_the_own_file_is_refused_with_no_request() -> anyhow::Result<()> {
    for subcommand in ["login", "logout"] {
        let mock = mock_cloud().await;
        let sandbox = Sandbox::new();
        std::fs::create_dir_all(sandbox.own_dir())?;
        std::fs::write(sandbox.own_file(), record("explicitly-configured"))?;
        let mut cmd = command(&sandbox, &mock.uri(), subcommand);
        cmd.env("EERO_MCP_SESSION_FILE", sandbox.own_file());

        let run = run(cmd, "user@example.com\n000001\n").await;

        assert_eq!(run.code, Some(1), "{subcommand}");
        assert!(
            run.stderr.contains("EERO_MCP_SESSION_FILE"),
            "{subcommand}: {}",
            run.stderr
        );
        assert_eq!(
            std::fs::read_to_string(sandbox.own_file())?,
            record("explicitly-configured"),
            "{subcommand}: nothing was written or deleted"
        );
        assert!(targets_of(&mock).await.is_empty(), "{subcommand}");
    }
    Ok(())
}

#[tokio::test]
async fn a_higher_precedence_token_is_noted_after_a_login() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    login_succeeds(&mock).await;
    let mut cmd = command(&sandbox, &mock.uri(), "login");
    cmd.env("RUSTEERO_SESSION_TOKEN", "env-token-0001");

    let run = run(cmd, "user@example.com\n000001\n").await;

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(run.stdout.contains("takes precedence"), "{}", run.stdout);
    assert!(
        run.stdout.contains("RUSTEERO_SESSION_TOKEN"),
        "{}",
        run.stdout
    );
    assert!(!run.stdout.contains("env-token-0001") && !run.stderr.contains("env-token-0001"));
    Ok(())
}

#[tokio::test]
async fn a_login_with_nowhere_to_store_the_session_exits_one_before_any_request()
-> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    let mut cmd = command(&sandbox, &mock.uri(), "login");
    // No own directory can be determined: no configuration directory, no home, and no keyring.
    cmd.env_remove("EERO_MCP_CONFIG_DIR")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("HOME")
        .env_remove("APPDATA");

    let run = run(cmd, "user@example.com\n000001\n").await;

    assert_eq!(run.code, Some(1));
    assert!(run.stderr.contains("EERO_MCP_CONFIG_DIR"), "{}", run.stderr);
    assert!(
        targets_of(&mock).await.is_empty(),
        "no message was triggered"
    );
    Ok(())
}

#[tokio::test]
async fn configuration_errors_end_every_subcommand_with_the_servers_message() -> anyhow::Result<()>
{
    for subcommand in ["login", "logout", "status"] {
        for (name, value) in [
            ("EERO_MCP_CONFIG_DIR", "relative/dir"),
            ("EERO_MCP_CONFIG_DIR", ""),
            ("EERO_MCP_NO_KEYRING", "0"),
            ("EERO_MCP_API_BASE_URL", "http://api-user.example.test"),
            ("RUSTEERO_SESSION_TOKEN", "bad\ntoken"),
        ] {
            let mock = mock_cloud().await;
            let sandbox = Sandbox::new();
            let mut cmd = command(&sandbox, &mock.uri(), subcommand);
            cmd.env(name, value);
            let run = run(cmd, "").await;
            assert_eq!(run.code, Some(1), "{subcommand} {name}");
            assert!(
                run.stderr.contains(name),
                "{subcommand} {name}: {}",
                run.stderr
            );
            assert!(
                !run.stderr.contains("bad"),
                "{subcommand} {name}: the value is not echoed"
            );
            assert_eq!(run.stdout, "", "{subcommand} {name}");
            assert!(targets_of(&mock).await.is_empty());
        }
    }
    Ok(())
}

// ===================== logout =====================

#[tokio::test]
async fn logout_signs_the_stored_session_out_deletes_it_and_names_the_keyring_as_not_checked()
-> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    std::fs::create_dir_all(sandbox.own_dir())?;
    std::fs::write(sandbox.own_file(), record(LOGIN_TOKEN))?;
    // Another credential file in the sandbox, which must stay byte-identical.
    std::fs::create_dir_all(sandbox.eeroctl_file().parent().expect("parent"))?;
    let other = record("some-other-session");
    std::fs::write(sandbox.eeroctl_file(), &other)?;
    mount_logout(&mock, LOGIN_TOKEN, 1).await;

    let run = run(command(&sandbox, &mock.uri(), "logout"), "").await;

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stdout.contains("sign-out request was sent"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("Removed"), "{}", run.stdout);
    assert!(
        run.stdout.contains("Not checked: the system keyring"),
        "EERO_MCP_NO_KEYRING is 1: {}",
        run.stdout
    );
    assert!(
        run.stdout.contains("eeroctl file"),
        "the next source: {}",
        run.stdout
    );
    run.assert_clean();
    assert!(!sandbox.own_file().exists());
    assert_eq!(std::fs::read_to_string(sandbox.eeroctl_file())?, other);
    assert_eq!(targets_of(&mock).await, ["POST /2.2/logout"]);
    Ok(())
}

#[tokio::test]
async fn logout_with_nothing_stored_sends_no_request_and_exits_zero() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();

    let run = run(command(&sandbox, &mock.uri(), "logout"), "").await;

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stdout.contains("No eero-mcp session was stored"),
        "{}",
        run.stdout
    );
    assert!(targets_of(&mock).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_stored_token_that_eeroctls_file_also_holds_is_deleted_locally_without_a_sign_out()
-> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    std::fs::create_dir_all(sandbox.own_dir())?;
    std::fs::write(sandbox.own_file(), record(LOGIN_TOKEN))?;
    std::fs::create_dir_all(sandbox.eeroctl_file().parent().expect("parent"))?;
    std::fs::write(sandbox.eeroctl_file(), record(LOGIN_TOKEN))?;

    let run = run(command(&sandbox, &mock.uri(), "logout"), "").await;

    assert_eq!(run.code, Some(0), "{}", run.stderr);
    assert!(
        run.stdout.contains("without signing out at eero") && run.stdout.contains("eeroctl file"),
        "the report says why: {}",
        run.stdout
    );
    assert!(!sandbox.own_file().exists(), "the local copy is gone");
    assert_eq!(
        std::fs::read_to_string(sandbox.eeroctl_file())?,
        record(LOGIN_TOKEN),
        "eeroctl's copy is untouched"
    );
    assert!(targets_of(&mock).await.is_empty(), "no sign-out request");
    run.assert_clean();
    Ok(())
}

// ===================== status =====================

#[tokio::test]
async fn status_reports_each_source_and_a_valid_session() -> anyhow::Result<()> {
    const TOKEN: &str = "status-token-0001";
    // (source name, how the token is provided)
    for source in [
        "environment token",
        "explicit file",
        "eero-mcp file",
        "eeroctl file",
    ] {
        let mock = mock_cloud().await;
        let sandbox = Sandbox::new();
        authed_get_as("/2.2/account", TOKEN)
            .respond_with(json_response(&fixture("account", "account")))
            .expect(1)
            .mount(&mock)
            .await;
        let mut cmd = command(&sandbox, &mock.uri(), "status");
        match source {
            "environment token" => {
                cmd.env("RUSTEERO_SESSION_TOKEN", TOKEN);
            }
            "explicit file" => {
                let explicit = sandbox.path("explicit.json");
                std::fs::write(&explicit, record(TOKEN))?;
                cmd.env("EERO_MCP_SESSION_FILE", &explicit);
            }
            "eero-mcp file" => {
                std::fs::create_dir_all(sandbox.own_dir())?;
                std::fs::write(sandbox.own_file(), record(TOKEN))?;
            }
            _ => {
                std::fs::create_dir_all(sandbox.eeroctl_file().parent().expect("parent"))?;
                std::fs::write(sandbox.eeroctl_file(), record(TOKEN))?;
            }
        }

        let run = run(cmd, "").await;

        assert_eq!(run.code, Some(0), "{source}: {}", run.stderr);
        assert!(
            run.stdout.contains(&format!("credential source: {source}")),
            "{source}: {}",
            run.stdout
        );
        assert!(
            run.stdout.contains("session: valid"),
            "{source}: {}",
            run.stdout
        );
        run.assert_clean();
        // No path, no account data.
        assert!(
            !run.stdout
                .contains(sandbox.dir.path().to_str().expect("utf-8"))
        );
        assert!(!run.stdout.contains("user-0001"));
        assert_eq!(targets_of(&mock).await, ["GET /2.2/account"]);
    }
    Ok(())
}

#[tokio::test]
async fn status_with_no_credential_exits_one_and_says_how_to_log_in() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();

    let run = run(command(&sandbox, &mock.uri(), "status"), "").await;

    assert_eq!(run.code, Some(1));
    assert!(
        run.stdout.contains("credential source: none"),
        "{}",
        run.stdout
    );
    assert!(run.stdout.contains("login subcommand"), "{}", run.stdout);
    assert!(targets_of(&mock).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn status_reports_a_rejected_and_an_unreachable_session() -> anyhow::Result<()> {
    const TOKEN: &str = "status-token-0001";
    // Rejected: eero answers 401 (the same token is found on the re-read? status does no re-read).
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    authed_get_as("/2.2/account", TOKEN)
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&mock)
        .await;
    let mut cmd = command(&sandbox, &mock.uri(), "status");
    cmd.env("RUSTEERO_SESSION_TOKEN", TOKEN);
    let rejected = run(cmd, "").await;
    assert_eq!(rejected.code, Some(1));
    assert!(
        rejected.stdout.contains("session: rejected"),
        "{}",
        rejected.stdout
    );
    assert!(
        rejected.stdout.contains("log in again"),
        "{}",
        rejected.stdout
    );
    rejected.assert_clean();

    // Unreachable: a loopback port nothing listens on.
    let sandbox = Sandbox::new();
    let mut cmd = command(&sandbox, "http://127.0.0.1:1", "status");
    cmd.env("RUSTEERO_SESSION_TOKEN", TOKEN);
    let unreachable = run(cmd, "").await;
    assert_eq!(unreachable.code, Some(1));
    assert!(
        unreachable
            .stdout
            .contains("session: unreachable (network failure)"),
        "{}",
        unreachable.stdout
    );
    unreachable.assert_clean();
    Ok(())
}

#[tokio::test]
async fn status_fails_like_the_server_for_a_bad_explicit_file() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    let mut cmd = command(&sandbox, &mock.uri(), "status");
    cmd.env("EERO_MCP_SESSION_FILE", sandbox.path("missing.json"));

    let run = run(cmd, "").await;

    assert_eq!(run.code, Some(1));
    assert!(
        run.stderr.contains("EERO_MCP_SESSION_FILE"),
        "{}",
        run.stderr
    );
    assert!(
        !run.stderr.contains("missing.json"),
        "no path: {}",
        run.stderr
    );
    assert!(targets_of(&mock).await.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_login_is_visible_to_status_and_undone_by_logout() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let sandbox = Sandbox::new();
    login_succeeds(&mock).await;
    authed_get_as("/2.2/account", LOGIN_TOKEN)
        .respond_with(json_response(&fixture("account", "account")))
        .expect(1)
        .mount(&mock)
        .await;
    mount_logout(&mock, LOGIN_TOKEN, 1).await;

    let login = run(
        command(&sandbox, &mock.uri(), "login"),
        "user@example.com\n000001\n",
    )
    .await;
    assert_eq!(login.code, Some(0), "{}", login.stderr);

    let status = run(command(&sandbox, &mock.uri(), "status"), "").await;
    assert_eq!(status.code, Some(0), "{}", status.stderr);
    assert!(
        status.stdout.contains("credential source: eero-mcp file"),
        "{}",
        status.stdout
    );

    let logout = run(command(&sandbox, &mock.uri(), "logout"), "").await;
    assert_eq!(logout.code, Some(0), "{}", logout.stderr);
    assert!(!sandbox.own_file().exists());

    let after = run(command(&sandbox, &mock.uri(), "status"), "").await;
    assert_eq!(after.code, Some(1));
    assert!(
        after.stdout.contains("credential source: none"),
        "{}",
        after.stdout
    );
    Ok(())
}
