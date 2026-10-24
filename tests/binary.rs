//! The `eero-mcp` binary as a process: the flags, the startup failures, and one real stdio session
//! against a mock cloud, proving that stdout carries only JSON-RPC, that the token never reaches
//! stderr (even under a debug log filter), and that closing stdin or sending a termination signal
//! ends the process with status 0.
//!
//! The child runs in a cleared environment: only `PATH` survives, and `HOME`, `APPDATA`,
//! `XDG_CONFIG_HOME`, `EEROCTL_CONFIG_DIR` and `EERO_MCP_CONFIG_DIR` point into an empty sandbox
//! directory, and `EERO_MCP_NO_KEYRING` is 1, so a child can never read the developer's eeroctl
//! file or eero-mcp directory, or reach the real keyring (a Keychain or Credential Manager on the
//! macOS and Windows runners). Every spawned process that gets as far as credential resolution
//! also gets `RUSTEERO_SESSION_TOKEN`, which ends it before the keyring and the files are
//! consulted. The child's environment is set on the `Command`; the test process never mutates
//! its own.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant};

use common::{authed_get_as, fixture, json_response, mock_cloud};
use serde_json::{Value, json};
use wiremock::MockServer;

const TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN: &str = "bin-token-0001";

/// An empty directory the child treats as its home and its eeroctl configuration directory. Nothing
/// ever writes to it.
fn sandbox() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("binary-sandbox");
        std::fs::create_dir_all(&dir).expect("the sandbox directory");
        dir
    })
}

/// The binary in a cleared environment (see the module docs).
fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_eero-mcp"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", sandbox())
        .env("APPDATA", sandbox())
        .env("XDG_CONFIG_HOME", sandbox())
        .env("EEROCTL_CONFIG_DIR", sandbox())
        .env("EERO_MCP_CONFIG_DIR", sandbox().join("eero-mcp-config"))
        .env("EERO_MCP_NO_KEYRING", "1");
    #[cfg(windows)]
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    command
}

struct Output {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

fn run(mut command: Command) -> Output {
    let output = command
        .stdin(Stdio::null())
        .output()
        .expect("the binary starts");
    Output {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

// ===================== flags =====================

#[test]
fn help_prints_usage_to_stdout_and_exits_zero() {
    for flag in ["--help", "-h"] {
        let output = run({
            let mut c = command();
            c.arg(flag);
            c
        });
        assert!(output.status.success(), "{flag}");
        assert!(output.stdout.contains("USAGE"), "{flag}");
        for variable in [
            "RUSTEERO_SESSION_TOKEN",
            "EERO_MCP_SESSION_FILE",
            "EEROCTL_CONFIG_DIR",
            "EERO_MCP_API_BASE_URL",
            "EERO_MCP_CONFIG_DIR",
            "EERO_MCP_NO_KEYRING",
            "RUST_LOG",
        ] {
            assert!(output.stdout.contains(variable), "{flag}: {variable}");
        }
        for subcommand in ["login", "logout", "status"] {
            assert!(output.stdout.contains(subcommand), "{flag}: {subcommand}");
        }
        assert_eq!(output.stderr, "", "{flag}");
    }
}

#[test]
fn version_prints_the_crate_version_to_stdout_and_exits_zero() {
    for flag in ["--version", "-V"] {
        let output = run({
            let mut c = command();
            c.arg(flag);
            c
        });
        assert!(output.status.success(), "{flag}");
        assert_eq!(
            output.stdout,
            format!("eero-mcp {}\n", env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
    }
}

#[test]
fn any_other_argument_is_refused_with_status_two_and_nothing_on_stdout() {
    for args in [
        vec!["--bogus"],
        vec!["serve"],
        vec!["--help", "extra"],
        vec!["--version", "--help"],
        // A subcommand takes no arguments of its own, and only the exact words count.
        vec!["login", "extra"],
        vec!["logout", "--force"],
        vec!["status", "--help"],
        vec!["login", "logout"],
        vec!["Login"],
        vec!["STATUS"],
        vec!["login "],
        vec![""],
    ] {
        let output = run({
            let mut c = command();
            c.args(&args);
            c
        });
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert_eq!(output.stdout, "", "{args:?}");
        assert!(
            output.stderr.contains("--help"),
            "{args:?}: {}",
            output.stderr
        );
    }
}

#[cfg(unix)]
#[test]
fn an_argument_that_is_not_utf8_is_a_usage_error_not_a_panic() {
    use std::os::unix::ffi::OsStringExt as _;

    let output = run({
        let mut c = command();
        c.arg(std::ffi::OsString::from_vec(vec![b'-', 0xff, 0xfe]));
        c
    });
    assert_eq!(output.status.code(), Some(2), "{}", output.stderr);
    assert_eq!(output.stdout, "");
    assert!(output.stderr.contains("--help"), "{}", output.stderr);
    assert!(!output.stderr.contains("panicked"), "{}", output.stderr);
}

#[test]
fn the_help_text_recommends_a_log_filter_that_excludes_rmcp() {
    let output = run({
        let mut c = command();
        c.arg("--help");
        c
    });
    assert!(
        output
            .stdout
            .contains("RUST_LOG=eero_mcp=debug,rusteero=debug"),
        "{}",
        output.stdout
    );
    // A bare filter also logs what rmcp sees of a login: the identifier argument at debug, the
    // form answers (identifier and one-time code) at trace.
    assert!(output.stdout.contains("trace"), "{}", output.stdout);
    assert!(output.stdout.contains("one-time code"), "{}", output.stdout);
}

// ===================== startup failures =====================

#[test]
fn an_invalid_session_token_fails_startup_without_echoing_it() {
    for bad in ["BADTOKENMARKER\n", "BADTOKENMARKER\r", ""] {
        let output = run({
            let mut c = command();
            c.env("RUSTEERO_SESSION_TOKEN", bad);
            c
        });
        assert_eq!(output.status.code(), Some(1), "{bad:?}");
        assert_eq!(output.stdout, "", "{bad:?}");
        assert!(
            output.stderr.contains("RUSTEERO_SESSION_TOKEN"),
            "{bad:?}: {}",
            output.stderr
        );
        assert!(
            !output.stderr.contains("BADTOKENMARKER"),
            "{bad:?}: {}",
            output.stderr
        );
    }
}

#[test]
fn a_rejected_api_base_url_fails_startup() {
    for bad in [
        "http://api-user.example.test",
        "ftp://localhost",
        "not a url",
        "",
    ] {
        let output = run({
            let mut c = command();
            c.env("RUSTEERO_SESSION_TOKEN", TOKEN)
                .env("EERO_MCP_API_BASE_URL", bad);
            c
        });
        assert_eq!(output.status.code(), Some(1), "{bad:?}");
        assert_eq!(output.stdout, "", "{bad:?}");
        assert!(
            output.stderr.contains("EERO_MCP_API_BASE_URL"),
            "{bad:?}: {}",
            output.stderr
        );
        assert!(
            !output.stderr.contains("example.test"),
            "{bad:?}: {}",
            output.stderr
        );
        assert!(!output.stderr.contains(TOKEN), "{bad:?}");
    }
}

#[test]
fn an_empty_explicit_session_file_variable_fails_startup() {
    let output = run({
        let mut c = command();
        c.env("EERO_MCP_SESSION_FILE", "");
        c
    });
    assert_eq!(output.status.code(), Some(1));
    assert!(
        output.stderr.contains("EERO_MCP_SESSION_FILE"),
        "{}",
        output.stderr
    );
}

// ===================== a real stdio session =====================

/// A spawned server with line-oriented JSON-RPC helpers.
struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    seen: Vec<String>,
    /// Drains the child's stderr while the session runs: the pipe holds 64 KiB, and a debug-level
    /// log of a large `tools/list` result would otherwise block the server on its next write.
    stderr: Option<std::thread::JoinHandle<String>>,
}

impl Session {
    fn start(origin: &str, log: Option<&str>) -> Self {
        let mut command = command();
        command
            .env("RUSTEERO_SESSION_TOKEN", TOKEN)
            .env("EERO_MCP_API_BASE_URL", origin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(filter) = log {
            command.env("RUST_LOG", filter);
        }
        let mut child = command.spawn().expect("the binary starts");
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("stdout is piped");
        let mut err = child.stderr.take().expect("stderr is piped");
        let stderr = Some(std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = std::io::Read::read_to_end(&mut err, &mut bytes);
            String::from_utf8_lossy(&bytes).into_owned()
        }));
        let (sender, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            lines,
            seen: Vec::new(),
            stderr,
        }
    }

    fn send(&mut self, message: &Value) {
        let stdin = self.stdin.as_mut().expect("stdin is open");
        writeln!(stdin, "{message}").expect("write a request");
        stdin.flush().expect("flush");
    }

    /// The next stdout line, which must be a JSON-RPC message.
    fn next_message(&mut self) -> Value {
        let line = match self.lines.recv_timeout(TIMEOUT) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => {
                panic!("no output within {TIMEOUT:?}; seen {:?}", self.seen)
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("stdout closed; seen {:?}", self.seen)
            }
        };
        self.seen.push(line.clone());
        let message: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("stdout carries only JSON-RPC, got {line:?}: {e}"));
        assert_eq!(message["jsonrpc"], "2.0", "{line}");
        message
    }

    /// Sends a request and returns the response with the same id.
    fn request(&mut self, id: u64, method: &str, params: &Value) -> Value {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        loop {
            let message = self.next_message();
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    fn handshake(&mut self) -> Value {
        let response = self.request(
            1,
            "initialize",
            &json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "binary-test", "version": "0"}
            }),
        );
        self.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        response
    }

    fn wait(&mut self) -> ExitStatus {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status;
            }
            assert!(started.elapsed() < TIMEOUT, "the process did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Everything the server wrote to stderr. Call it after `wait()`: the reader ends at EOF.
    fn stderr(&mut self) -> String {
        self.stderr
            .take()
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stdio_session_serves_tools_and_exits_zero_when_stdin_closes() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    authed_get_as("/2.2/account", TOKEN)
        .respond_with(json_response(&fixture("account", "account")))
        .expect(1)
        .mount(&mock)
        .await;
    let origin = mock.uri();

    let (status, stderr) = tokio::task::spawn_blocking(move || {
        // A debug filter makes rusteero log request paths: the token must still never appear.
        let mut session = Session::start(&origin, Some("debug"));

        let init = session.handshake();
        assert_eq!(init["result"]["serverInfo"]["name"], "eero-mcp");
        assert_eq!(
            init["result"]["serverInfo"]["version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
        assert_eq!(init["result"]["capabilities"], json!({"tools": {}}));

        let listed = session.request(2, "tools/list", &json!({}));
        let names: Vec<&str> = listed["result"]["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert!(names.contains(&"get_account"), "{names:?}");

        let called = session.request(
            3,
            "tools/call",
            &json!({"name": "get_account", "arguments": {}}),
        );
        assert_eq!(called["result"]["isError"], false, "{called}");
        assert_eq!(
            called["result"]["structuredContent"]["data"]["id"],
            "user-0001"
        );

        // Closing stdin is the host going away: the process exits 0.
        drop(session.stdin.take());
        let status = session.wait();
        let stderr = session.stderr();
        (status, stderr)
    })
    .await?;

    assert!(status.success(), "{status:?}");
    assert!(
        !stderr.contains(TOKEN),
        "the token reached stderr:\n{stderr}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_call_is_an_in_band_error_on_stdout() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    authed_get_unauthorised(&mock).await;
    let origin = mock.uri();

    let called = tokio::task::spawn_blocking(move || {
        let mut session = Session::start(&origin, None);
        session.handshake();
        let called = session.request(
            2,
            "tools/call",
            &json!({"name": "get_account", "arguments": {}}),
        );
        drop(session.stdin.take());
        assert!(session.wait().success());
        called
    })
    .await?;

    assert_eq!(called["result"]["isError"], true, "{called}");
    let text = called["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    let error: Value = serde_json::from_str(text)?;
    assert_eq!(error["error"]["code"], "authentication_required");
    assert!(!text.contains(TOKEN));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_login_tool_without_form_support_asks_for_the_terminal_and_sends_nothing()
-> anyhow::Result<()> {
    const IDENTIFIER: &str = "binary-user@example.com";
    // The mock's write tripwire fails the test if any POST reaches it.
    let mock = mock_cloud().await;
    let origin = mock.uri();

    let (called, stderr) = tokio::task::spawn_blocking(move || {
        // A scoped debug filter: eero-mcp and rusteero log freely, rmcp stays quiet.
        let mut session = Session::start(&origin, Some("eero_mcp=debug,rusteero=debug"));
        // The handshake declares no capabilities, so no elicitation: the code could not be asked
        // for without passing through the model.
        let init = session.handshake();
        let capabilities = init["result"]["capabilities"].clone();
        let called = session.request(
            2,
            "tools/call",
            &json!({"name": "login", "arguments": {"identifier": IDENTIFIER}}),
        );
        drop(session.stdin.take());
        assert!(session.wait().success());
        ((capabilities, called), session.stderr())
    })
    .await?;
    let (capabilities, called) = called;

    // Elicitation is a client capability: the server declares tools only.
    assert_eq!(capabilities, json!({"tools": {}}));
    assert_eq!(called["result"]["isError"], true, "{called}");
    let text = called["result"]["content"][0]["text"]
        .as_str()
        .expect("text");
    let error: Value = serde_json::from_str(text)?;
    assert_eq!(error["error"]["code"], "login_requires_terminal");
    assert!(!text.contains(IDENTIFIER));
    assert!(
        !stderr.contains(IDENTIFIER) && !stderr.contains(TOKEN),
        "neither the identifier nor the token reaches stderr:\n{stderr}"
    );
    assert!(
        mock.received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
    );
    Ok(())
}

/// `GET /2.2/account` answers 401 to the binary's token. The environment token never changes, so
/// the re-read finds the same token and the call fails with `authentication_required`.
async fn authed_get_unauthorised(mock: &MockServer) {
    authed_get_as("/2.2/account", TOKEN)
        .respond_with(wiremock::ResponseTemplate::new(401))
        .expect(1)
        .mount(mock)
        .await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_termination_signal_ends_the_server_with_status_zero() -> anyhow::Result<()> {
    let mock = mock_cloud().await;
    let origin = mock.uri();

    let statuses = tokio::task::spawn_blocking(move || {
        // Signal right after the handshake, several times: the handlers must already be installed
        // when the InitializeResult is written, not merely soon after.
        (0..5)
            .map(|_| {
                let mut session = Session::start(&origin, None);
                session.handshake();
                // The server is serving; ask it to stop the way a host or a supervisor would.
                terminate(session.child.id());
                session.wait()
            })
            .collect::<Vec<_>>()
    })
    .await?;

    for status in statuses {
        assert!(status.success(), "{status:?}");
    }
    Ok(())
}

#[cfg(unix)]
fn terminate(pid: u32) {
    let signalled = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("kill is available");
    assert!(signalled.success());
}

/// Kills the child when the test ends, however it ends.
#[cfg(unix)]
struct KillOnDrop(Child);

#[cfg(unix)]
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
#[test]
fn a_termination_signal_before_the_handshake_ends_the_server_with_status_zero() {
    // No token, and the sandbox holds no credential file: once the server has installed its
    // signal handlers and read its configuration it warns about the missing credential. That
    // line is the sign that a signal is now handled, and the server is still waiting for the
    // host's initialize request.
    let mut child = KillOnDrop(
        command()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the binary starts"),
    );
    let _stdin = child.0.stdin.take();
    let stderr = child.0.stderr.take().expect("stderr is piped");
    let (sender, lines) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let started = Instant::now();
    loop {
        let line = lines
            .recv_timeout(TIMEOUT.saturating_sub(started.elapsed()))
            .expect("the server warns that it has no credential");
        if line.contains("no eero credential found") {
            break;
        }
    }

    terminate(child.0.id());

    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("try_wait") {
            break status;
        }
        assert!(started.elapsed() < TIMEOUT, "the process did not exit");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "{status:?}");
}
