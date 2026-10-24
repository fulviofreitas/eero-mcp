//! The login tool (tool 41) end to end: an in-process MCP client that implements elicitation and
//! answers each form from a script, against a server wired to the shared mock cloud.
//!
//! What this proves, case by case: the identifier form and the code form (typed forms with one
//! required text field each), the session saved to the own store and installed in the running
//! server, every refusal and cancellation path, the fallback for clients that cannot show forms
//! (`login_requires_terminal`, zero requests), the cancellation of the tool call (the login lock
//! is free afterwards, nothing is saved, nothing more is sent), the progress notifications, and the
//! pickup of a terminal login by a running server.
//!
//! Every mock comes from `common::mock_cloud()` (write tripwire mounted); the login POSTs a test
//! expects are mounted above it with pinned counts. Values are synthetic. No test touches the real
//! keyring (`EERO_MCP_NO_KEYRING=1`), eeroctl's file or the real eero-mcp directory, and no
//! test waits out the 10-minute form timeout: the timeout is made short through the same code
//! path.

mod common;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    CODE, CODE_2, IDENTIFIER, LOGIN_TOKEN, LOGIN_TOKEN_2, authed_get_as, error_json, fixture,
    json_response, mock_cloud, mount_logout, mount_resend, mount_start, mount_start_error,
    mount_verify_error, mount_verify_ok, structured, targets_of,
};
use eero_mcp::auth::{OwnStore, save_session};
use eero_mcp::config::{EnvMap, Settings};
use eero_mcp::credentials::{CredentialChain, Resolver, SystemSources};
use eero_mcp::tools::login::LoginSupport;
use eero_mcp::{EeroMcp, client_builder};
use rmcp::model::{
    CallToolRequest, CallToolRequestParams, CallToolResult, ClientCapabilities, ClientConfig,
    ClientRequest, ElicitRequestParams, ElicitResult, ElicitationAction, ElicitationCapability,
    Implementation, ProgressNotificationParam, ServerResult, UrlElicitationCapability,
};
use rmcp::service::{NotificationContext, PeerRequestOptions, RequestContext, RunningService};
use rmcp::{ClientHandler, ErrorData, RoleClient, ServiceExt as _, object};
use secrecy::SecretString;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::{Notify, Semaphore};
use wiremock::MockServer;

// ===================== the scripted client =====================

/// What the scripted client does with one form.
#[derive(Clone)]
enum Reply {
    /// Accept, with this content.
    Accept(Value),
    Decline,
    Cancel,
    /// Accept with a form that is not an object of the expected shape.
    Empty,
    /// Hold the form open until the test releases it, then do the inner reply.
    Hold(Box<Reply>),
}

fn accept(field: &str, value: &str) -> Reply {
    Reply::Accept(json!({ field: value }))
}

fn identifier() -> Reply {
    accept("identifier", IDENTIFIER)
}

fn code(value: &str) -> Reply {
    accept("code", value)
}

/// One form as the client saw it.
#[derive(Debug, Clone)]
struct Shown {
    message: String,
    schema: Value,
}

struct ScriptedClient {
    config: ClientConfig,
    replies: Mutex<VecDeque<Reply>>,
    shown: Arc<Mutex<Vec<Shown>>>,
    progress: Arc<Mutex<Vec<String>>>,
    /// Notified whenever a form arrives.
    arrived: Arc<Semaphore>,
    /// Releases a held form.
    release: Arc<Notify>,
}

impl ClientHandler for ScriptedClient {
    fn get_info(&self) -> ClientConfig {
        self.config.clone()
    }

    async fn create_elicitation(
        &self,
        request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, ErrorData> {
        if let ElicitRequestParams::FormElicitationParams {
            message,
            requested_schema,
            ..
        } = &request
        {
            self.shown.lock().expect("lock").push(Shown {
                message: message.clone(),
                schema: serde_json::to_value(requested_schema).expect("schema"),
            });
        }
        self.arrived.add_permits(1);
        let mut reply = self
            .replies
            .lock()
            .expect("lock")
            .pop_front()
            .expect("one scripted reply per form");
        while let Reply::Hold(inner) = reply {
            self.release.notified().await;
            reply = *inner;
        }
        Ok(match reply {
            Reply::Accept(content) => {
                ElicitResult::new(ElicitationAction::Accept).with_content(content)
            }
            Reply::Decline => ElicitResult::new(ElicitationAction::Decline),
            Reply::Cancel => ElicitResult::new(ElicitationAction::Cancel),
            Reply::Empty => ElicitResult::new(ElicitationAction::Accept),
            Reply::Hold(_) => unreachable!("holds are resolved above"),
        })
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        self.progress
            .lock()
            .expect("lock")
            .push(params.message.unwrap_or_default());
    }
}

/// How the client declares elicitation in its handshake.
#[derive(Clone, Copy)]
enum Capability {
    /// Form mode.
    Form,
    /// A bare elicitation capability, which counts as form mode.
    Bare,
    /// No elicitation capability at all.
    None,
    /// URL mode only: no form can be shown.
    UrlOnly,
}

fn client_config(capability: Capability) -> ClientConfig {
    let capabilities = match capability {
        Capability::Form => {
            let mut capabilities = ClientCapabilities::default();
            capabilities.elicitation = Some(
                ElicitationCapability::new()
                    .with_form(rmcp::model::FormElicitationCapability::new()),
            );
            capabilities
        }
        Capability::Bare => ClientCapabilities::builder().enable_elicitation().build(),
        Capability::None => ClientCapabilities::default(),
        Capability::UrlOnly => {
            let mut capabilities = ClientCapabilities::default();
            capabilities.elicitation =
                Some(ElicitationCapability::new().with_url(UrlElicitationCapability::new()));
            capabilities
        }
    };
    ClientConfig::new(capabilities, Implementation::new("login-test-client", "0"))
}

// ===================== the rig =====================

struct Options {
    capability: Capability,
    replies: Vec<Reply>,
    /// Extra environment for the settings.
    env: Vec<(String, String)>,
    /// Build the server with login support (the default).
    login_support: bool,
    form_timeout: Option<Duration>,
    progress_interval: Option<Duration>,
}

impl Options {
    fn new(replies: Vec<Reply>) -> Self {
        Self {
            capability: Capability::Form,
            replies,
            env: Vec::new(),
            login_support: true,
            form_timeout: None,
            progress_interval: None,
        }
    }

    fn capability(mut self, capability: Capability) -> Self {
        self.capability = capability;
        self
    }

    fn env(mut self, name: &str, value: &str) -> Self {
        self.env.push((name.to_owned(), value.to_owned()));
        self
    }
}

struct Rig {
    mock: MockServer,
    dir: TempDir,
    client: RunningService<RoleClient, ScriptedClient>,
    chain: Arc<CredentialChain>,
    settings: Settings,
    shown: Arc<Mutex<Vec<Shown>>>,
    progress: Arc<Mutex<Vec<String>>>,
    arrived: Arc<Semaphore>,
    release: Arc<Notify>,
}

impl Rig {
    async fn start(options: Options) -> anyhow::Result<Self> {
        let mock = mock_cloud().await;
        let dir = tempfile::tempdir()?;
        let own_dir = dir.path().join("cfg");
        let mut pairs: Vec<(String, String)> = vec![
            (
                "EERO_MCP_CONFIG_DIR".to_owned(),
                own_dir.to_str().expect("utf-8").to_owned(),
            ),
            ("EERO_MCP_NO_KEYRING".to_owned(), "1".to_owned()),
            ("EERO_MCP_API_BASE_URL".to_owned(), mock.uri()),
        ];
        pairs.extend(options.env);
        let settings = Settings::from_env_for(&EnvMap::from_pairs(pairs), false)?;
        let chain = Arc::new(CredentialChain::new(&settings, Arc::new(SystemSources)));

        // The server's Client starts without a session; the resolver is the real chain, so a
        // saved login is also found by a re-read.
        let eero = client_builder(Some(&mock.uri()), None::<&SecretString>)
            .build()
            .await?;
        let mut server = EeroMcp::new(eero, Resolver::new(Arc::clone(&chain)));
        if options.login_support {
            let mut support = LoginSupport::new(
                settings.api_base_url.clone(),
                OwnStore::production(&settings),
                Arc::clone(&chain),
            );
            if let Some(timeout) = options.form_timeout {
                support = support.with_form_timeout(timeout);
            }
            if let Some(interval) = options.progress_interval {
                support = support.with_progress_interval(interval);
            }
            server = server.with_login(support);
        }

        let shown = Arc::new(Mutex::new(Vec::new()));
        let progress = Arc::new(Mutex::new(Vec::new()));
        let arrived = Arc::new(Semaphore::new(0));
        let release = Arc::new(Notify::new());
        let scripted = ScriptedClient {
            config: client_config(options.capability),
            replies: Mutex::new(options.replies.into()),
            shown: Arc::clone(&shown),
            progress: Arc::clone(&progress),
            arrived: Arc::clone(&arrived),
            release: Arc::clone(&release),
        };

        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let running = server.serve(server_io).await?;
            running.waiting().await?;
            anyhow::Ok(())
        });
        let client = scripted.serve(client_io).await?;
        Ok(Self {
            mock,
            dir,
            client,
            chain,
            settings,
            shown,
            progress,
            arrived,
            release,
        })
    }

    fn own_file(&self) -> PathBuf {
        self.dir.path().join("cfg").join("session.json")
    }

    async fn login(&self, arguments: Value) -> anyhow::Result<CallToolResult> {
        let mut params = CallToolRequestParams::new("login");
        if let Value::Object(map) = arguments {
            params = params.with_arguments(map);
        }
        Ok(self.client.call_tool(params).await?)
    }

    /// Waits until `count` more forms have reached the client. Arrivals are counted, not merely
    /// signalled, so two forms that arrive before the test looks are both seen.
    async fn forms_arrived(&self, count: u32) {
        self.arrived
            .acquire_many(count)
            .await
            .expect("the semaphore is never closed")
            .forget();
    }

    fn shown(&self) -> Vec<Shown> {
        self.shown.lock().expect("lock").clone()
    }

    fn progress(&self) -> Vec<String> {
        self.progress.lock().expect("lock").clone()
    }

    /// Calls `get_account` and returns the raw result.
    async fn get_account(&self) -> anyhow::Result<CallToolResult> {
        Ok(self
            .client
            .call_tool(CallToolRequestParams::new("get_account").with_arguments(object!({})))
            .await?)
    }
}

/// The `{"error": {...}}` object of a failed login.
fn error_of(result: &CallToolResult) -> anyhow::Result<Value> {
    Ok(error_json(result)?["error"].clone())
}

/// None of the secrets appears in `text`.
fn assert_clean(text: &str) {
    for secret in [
        IDENTIFIER,
        CODE,
        CODE_2,
        LOGIN_TOKEN,
        LOGIN_TOKEN_2,
        "000001",
    ] {
        assert!(!text.contains(secret), "{secret} leaked into: {text}");
    }
}

/// Neither copy of a result, nor any form message, carries a secret.
fn assert_result_clean(result: &CallToolResult) {
    assert_clean(&serde_json::to_string(result).expect("result"));
}

async fn mount_account_for(rig: &Rig, token: &str, calls: u64) {
    authed_get_as("/2.2/account", token)
        .respond_with(json_response(&fixture("account", "account")))
        .expect(calls)
        .mount(&rig.mock)
        .await;
}

// ===================== success =====================

#[tokio::test]
async fn a_login_asks_two_forms_saves_the_session_and_installs_it() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![identifier(), code(CODE)])).await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;
    mount_account_for(&rig, LOGIN_TOKEN, 1).await;

    let result = rig.login(json!({})).await?;

    let value = structured(&result)?;
    assert_eq!(value["data"], json!({"logged_in": true, "store": "file"}));
    assert!(value.get("network_id").is_none() && value.get("server_time").is_none());
    assert_result_clean(&result);

    // The own file holds the session, in the eero-api record shape.
    let saved: Value = serde_json::from_str(&std::fs::read_to_string(rig.own_file())?)?;
    assert_eq!(saved["session_id"], LOGIN_TOKEN);
    assert_eq!(saved["schema_version"], 2);

    // The running server uses it at once: the next read carries it in both credential headers.
    let account = structured(&rig.get_account().await?)?;
    assert_eq!(account["data"]["id"], "user-0001");

    // Exactly one start, one verify, one read; no resend.
    assert_eq!(
        targets_of(&rig.mock).await,
        [
            "POST /2.2/login",
            "POST /2.2/login/verify",
            "GET /2.2/account"
        ]
    );

    // Two forms, each one required text field, and no message that echoes a secret.
    let shown = rig.shown();
    assert_eq!(shown.len(), 2);
    for (form, field) in shown.iter().zip(["identifier", "code"]) {
        assert_eq!(form.schema["type"], "object", "{}", form.schema);
        assert_eq!(form.schema["required"], json!([field]), "{}", form.schema);
        let properties = form.schema["properties"].as_object().expect("properties");
        assert_eq!(properties.len(), 1, "no optional field: {}", form.schema);
        assert_eq!(properties[field]["type"], "string");
        assert!(
            properties[field]["description"]
                .as_str()
                .is_some_and(|d| d.len() >= 10),
            "{}",
            form.schema
        );
        assert_clean(&form.message);
    }
    assert!(
        shown[1].schema["properties"]["code"]["description"]
            .as_str()
            .unwrap_or_default()
            .contains("new"),
        "the code field says to type new for a new code: {}",
        shown[1].schema
    );
    Ok(())
}

#[tokio::test]
async fn a_bare_elicitation_capability_counts_as_form_mode() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![identifier(), code(CODE)]).capability(Capability::Bare))
        .await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;

    let result = rig.login(json!({})).await?;
    assert_eq!(structured(&result)?["data"]["logged_in"], true);
    Ok(())
}

#[tokio::test]
async fn an_identifier_argument_skips_the_identifier_form() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![code(CODE)])).await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;

    let result = rig
        .login(json!({"identifier": "  user@example.com "}))
        .await?;

    assert_eq!(structured(&result)?["data"]["store"], "file");
    let shown = rig.shown();
    assert_eq!(shown.len(), 1, "only the code form");
    assert_eq!(shown[0].schema["required"], json!(["code"]));
    assert_result_clean(&result);
    Ok(())
}

#[tokio::test]
async fn a_wrong_code_restarts_the_login_and_the_second_code_succeeds() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![identifier(), code(CODE), code(CODE_2)])).await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN_2, 1).await;
    mount_verify_error(
        &rig.mock,
        LOGIN_TOKEN,
        CODE,
        401,
        Some("error.verification.invalid"),
        1,
    )
    .await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN_2, CODE_2, 1).await;
    mount_account_for(&rig, LOGIN_TOKEN_2, 1).await;

    let result = rig.login(json!({})).await?;

    assert_eq!(structured(&result)?["data"]["logged_in"], true);
    assert_eq!(
        targets_of(&rig.mock).await,
        [
            "POST /2.2/login",
            "POST /2.2/login/verify",
            "POST /2.2/login",
            "POST /2.2/login/verify"
        ]
    );
    // Two code forms, the second saying a new code was sent.
    let shown = rig.shown();
    assert_eq!(shown.len(), 3);
    assert!(
        shown[2].message.contains("not accepted"),
        "{}",
        shown[2].message
    );
    // The second session is the one installed.
    structured(&rig.get_account().await?)?;
    assert!(
        std::fs::read_to_string(rig.own_file())?.contains(LOGIN_TOKEN_2),
        "the second session is the saved one"
    );
    Ok(())
}

#[tokio::test]
async fn new_as_the_code_resends_once_and_the_next_code_verifies() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![identifier(), code("New"), code(CODE)])).await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_resend(&rig.mock, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;

    let result = rig.login(json!({})).await?;

    assert_eq!(structured(&result)?["data"]["logged_in"], true);
    assert_eq!(
        targets_of(&rig.mock).await,
        [
            "POST /2.2/login",
            "POST /2.2/login/resend",
            "POST /2.2/login/verify"
        ]
    );
    assert!(
        rig.shown()[2].message.contains("again"),
        "{}",
        rig.shown()[2].message
    );
    Ok(())
}

#[tokio::test]
async fn invalid_form_entries_show_the_form_again_with_a_notice() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![
        accept("identifier", "   "),
        identifier(),
        code("not a code"),
        code(CODE),
    ]))
    .await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;

    let result = rig.login(json!({})).await?;

    assert_eq!(structured(&result)?["data"]["logged_in"], true);
    let shown = rig.shown();
    assert_eq!(shown.len(), 4);
    assert!(
        shown[1].message.contains("does not look like"),
        "{}",
        shown[1].message
    );
    assert!(
        shown[3].message.contains("does not look like"),
        "{}",
        shown[3].message
    );
    // The malformed code sent nothing.
    assert_eq!(targets_of(&rig.mock).await.len(), 2);
    Ok(())
}

// ===================== refusals =====================

#[tokio::test]
async fn declining_or_cancelling_a_form_cancels_the_login_and_saves_nothing() -> anyhow::Result<()>
{
    // (the replies, the number of POSTs that reach eero)
    let cases: Vec<(Vec<Reply>, usize)> = vec![
        (vec![Reply::Decline], 0),
        (vec![Reply::Cancel], 0),
        (vec![identifier(), Reply::Decline], 1),
        (vec![identifier(), Reply::Cancel], 1),
    ];
    for (replies, posts) in cases {
        let rig = Rig::start(Options::new(replies)).await?;
        if posts > 0 {
            mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
        }

        let result = rig.login(json!({})).await?;

        let error = error_of(&result)?;
        assert_eq!(error["code"], "login_cancelled");
        assert_result_clean(&result);
        assert_eq!(targets_of(&rig.mock).await.len(), posts);
        assert!(!rig.own_file().exists(), "nothing was saved");
        // Nothing was installed either.
        let read = error_of(&rig.get_account().await?)?;
        assert_eq!(read["code"], "authentication_required");
    }
    Ok(())
}

#[tokio::test]
async fn three_wrong_codes_fail_the_login_after_three_starts() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![
        identifier(),
        code(CODE),
        code(CODE),
        code(CODE),
    ]))
    .await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 3).await;
    mount_verify_error(
        &rig.mock,
        LOGIN_TOKEN,
        CODE,
        401,
        Some("error.verification.invalid"),
        3,
    )
    .await;

    let result = rig.login(json!({})).await?;

    let error = error_of(&result)?;
    assert_eq!(error["code"], "login_failed");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("3 attempts")
    );
    assert_result_clean(&result);
    assert!(!rig.own_file().exists());
    Ok(())
}

#[tokio::test]
async fn a_blocked_verification_fails_the_login_after_one_start() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![identifier(), code(CODE), code(CODE)])).await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_error(
        &rig.mock,
        LOGIN_TOKEN,
        CODE,
        401,
        Some("error.verification.blocked"),
        1,
    )
    .await;

    let result = rig.login(json!({})).await?;

    let error = error_of(&result)?;
    assert_eq!(error["code"], "login_failed");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("refused")
    );
    assert_eq!(rig.shown().len(), 2, "no further code form");
    assert_eq!(targets_of(&rig.mock).await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn a_refused_start_fails_the_login_with_the_amazon_hint() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![identifier()])).await?;
    mount_start_error(
        &rig.mock,
        IDENTIFIER,
        400,
        "error.user.amazon_login.exists",
        1,
    )
    .await;

    let result = rig.login(json!({})).await?;

    let error = error_of(&result)?;
    assert_eq!(error["code"], "login_failed");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("Amazon")
    );
    assert_result_clean(&result);
    assert_eq!(rig.shown().len(), 1, "no code form");
    Ok(())
}

#[tokio::test]
async fn rate_limits_keep_their_own_code_and_carry_the_wait() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![identifier()])).await?;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .and(wiremock::matchers::path("/2.2/login"))
        .respond_with(
            wiremock::ResponseTemplate::new(429)
                .insert_header("Retry-After", "30")
                .set_body_raw("{}", "application/json"),
        )
        .with_priority(1)
        .expect(1)
        .mount(&rig.mock)
        .await;

    let error = error_of(&rig.login(json!({})).await?)?;

    assert_eq!(error["code"], "rate_limited");
    assert_eq!(error["retry_after_seconds"], 30);
    Ok(())
}

#[tokio::test]
async fn a_form_answer_without_usable_content_fails_with_fixed_text() -> anyhow::Result<()> {
    for reply in [
        Reply::Empty,
        // The wrong field name: the typed form cannot parse it, and its parse error would print
        // the received data.
        Reply::Accept(json!({"nope": IDENTIFIER})),
        Reply::Accept(json!({"identifier": 5})),
    ] {
        let rig = Rig::start(Options::new(vec![reply])).await?;
        let result = rig.login(json!({})).await?;
        let error = error_of(&result)?;
        assert_eq!(error["code"], "login_failed");
        assert_result_clean(&result);
        assert!(targets_of(&rig.mock).await.is_empty());
    }
    Ok(())
}

// ===================== the identifier argument =====================

#[tokio::test]
async fn an_invalid_identifier_argument_is_invalid_argument_before_any_request()
-> anyhow::Result<()> {
    let long = "x".repeat(255);
    let cases: Vec<Value> = vec![
        json!({"identifier": ""}),
        json!({"identifier": "   "}),
        json!({"identifier": long}),
        json!({"identifier": "user@exa\nmple.com"}),
        // Not a string: a phone number sent as a number would lose its plus sign or zeros.
        json!({"identifier": 15_555_550_100_u64}),
        json!({"identifier": 5}),
        json!({"identifier": true}),
        json!({"identifier": ["user@example.com"]}),
        json!({"identifier": {"value": "user@example.com"}}),
    ];
    for arguments in cases {
        let rig = Rig::start(Options::new(vec![])).await?;
        let result = rig.login(arguments.clone()).await?;
        let error = error_of(&result)?;
        assert_eq!(error["code"], "invalid_argument", "{arguments}");
        assert_eq!(error["field"], "identifier", "{arguments}");
        // The fixed message is neither rmcp's deserialisation text nor an echo of the value.
        let text = serde_json::to_string(&result)?;
        assert!(!text.contains("deserialize"), "{text}");
        assert!(
            !text.contains("15555550100") && !text.contains("example.com"),
            "{text}"
        );
        assert!(rig.shown().is_empty(), "no form was shown");
        assert!(targets_of(&rig.mock).await.is_empty(), "zero requests");
    }
    Ok(())
}

#[tokio::test]
async fn unknown_input_fields_are_rejected_before_anything_else() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![])).await?;
    // The one-time code is never an input.
    for arguments in [
        json!({"code": "000001"}),
        json!({"identifier": IDENTIFIER, "otp": "1"}),
    ] {
        let result = rig.login(arguments).await?;
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().expect("text").text.clone();
        assert!(
            text.starts_with("failed to deserialize parameters"),
            "{text}"
        );
    }
    assert!(targets_of(&rig.mock).await.is_empty());
    assert!(rig.shown().is_empty());
    Ok(())
}

// ===================== clients that cannot show forms =====================

#[tokio::test]
async fn a_client_without_form_support_gets_login_requires_terminal_and_nothing_is_sent()
-> anyhow::Result<()> {
    for capability in [Capability::None, Capability::UrlOnly] {
        let rig = Rig::start(Options::new(vec![]).capability(capability)).await?;

        // With and without an identifier argument: nothing is sent either way.
        for arguments in [json!({}), json!({"identifier": IDENTIFIER})] {
            let result = rig.login(arguments).await?;
            let error = error_of(&result)?;
            assert_eq!(error["code"], "login_requires_terminal");
            assert!(
                error["message"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("login subcommand"),
                "{error}"
            );
            assert_result_clean(&result);
        }
        assert!(rig.shown().is_empty());
        assert!(targets_of(&rig.mock).await.is_empty(), "zero requests");
        assert!(!rig.own_file().exists());
    }
    Ok(())
}

#[tokio::test]
async fn a_request_on_protocol_2026_07_28_gets_login_requires_terminal() -> anyhow::Result<()> {
    // That protocol forbids server-to-client requests, so no form could be sent. A request
    // carries its protocol version in its metadata.
    let rig = Rig::start(Options::new(vec![identifier(), code(CODE)])).await?;
    // Even a client that declares form support in its meta gets no form on that protocol.
    let config = client_config(Capability::Form);
    let meta = rmcp::model::RequestMetaObject::with_client_context(
        rmcp::model::ProtocolVersion::V_2026_07_28,
        config.client_info,
        config.capabilities,
    );
    let request = ClientRequest::CallToolRequest(CallToolRequest::new(
        CallToolRequestParams::new("login").with_arguments(object!({})),
    ));
    let mut options = PeerRequestOptions::no_options();
    options.meta = Some(meta);
    let handle = rig
        .client
        .peer()
        .send_cancellable_request(request, options)
        .await?;
    let ServerResult::CallToolResult(result) = handle.await_response().await? else {
        anyhow::bail!("not a tool result");
    };
    assert_eq!(error_of(&result)?["code"], "login_requires_terminal");
    assert!(targets_of(&rig.mock).await.is_empty());
    assert!(rig.shown().is_empty());
    Ok(())
}

#[tokio::test]
async fn a_server_built_without_login_support_answers_that_login_is_unavailable()
-> anyhow::Result<()> {
    let mut options = Options::new(vec![identifier()]);
    options.login_support = false;
    let rig = Rig::start(options).await?;

    let error = error_of(&rig.login(json!({})).await?)?;

    assert_eq!(error["code"], "login_failed");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not available")
    );
    assert!(
        targets_of(&rig.mock).await.is_empty(),
        "nothing can reach eero"
    );
    Ok(())
}

// ===================== the explicit file, precedence, a failed save =====================

#[tokio::test]
async fn an_explicit_file_that_is_the_own_file_fails_the_login_with_zero_requests()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let own = dir.path().join("cfg").join("session.json");
    let rig = Rig::start(
        Options::new(vec![identifier(), code(CODE)])
            .env(
                "EERO_MCP_CONFIG_DIR",
                dir.path().join("cfg").to_str().expect("utf-8"),
            )
            .env("EERO_MCP_SESSION_FILE", own.to_str().expect("utf-8")),
    )
    .await?;
    // The explicit file exists (startup would otherwise fail on the server side of things).
    std::fs::create_dir_all(own.parent().expect("parent"))?;
    std::fs::write(
        &own,
        r#"{"session_id":"explicitly-configured","schema_version":2}"#,
    )?;

    let error = error_of(&rig.login(json!({})).await?)?;

    assert_eq!(error["code"], "login_failed");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("EERO_MCP_SESSION_FILE")
    );
    assert!(targets_of(&rig.mock).await.is_empty());
    assert!(rig.shown().is_empty());
    assert_eq!(
        std::fs::read_to_string(&own)?,
        r#"{"session_id":"explicitly-configured","schema_version":2}"#,
        "the configured credential was not touched"
    );
    Ok(())
}

#[tokio::test]
async fn a_higher_precedence_source_is_noted_in_the_result() -> anyhow::Result<()> {
    // The environment token wins over the own store.
    let rig = Rig::start(
        Options::new(vec![identifier(), code(CODE)])
            .env("RUSTEERO_SESSION_TOKEN", "env-token-0001"),
    )
    .await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;
    let value = structured(&rig.login(json!({})).await?)?;
    let notes = value["data"]["notes"].as_array().expect("notes");
    assert_eq!(notes.len(), 1);
    assert!(
        notes[0]
            .as_str()
            .unwrap_or_default()
            .contains("RUSTEERO_SESSION_TOKEN")
    );
    assert!(!value.to_string().contains("env-token-0001"));

    // So does a usable explicit file.
    let dir = tempfile::tempdir()?;
    let explicit = dir.path().join("explicit.json");
    std::fs::write(
        &explicit,
        r#"{"session_id":"explicit-0001","schema_version":2}"#,
    )?;
    let rig = Rig::start(
        Options::new(vec![identifier(), code(CODE)])
            .env("EERO_MCP_SESSION_FILE", explicit.to_str().expect("utf-8")),
    )
    .await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;
    let value = structured(&rig.login(json!({})).await?)?;
    let notes = value["data"]["notes"].as_array().expect("notes");
    assert!(
        notes[0]
            .as_str()
            .unwrap_or_default()
            .contains("EERO_MCP_SESSION_FILE")
    );
    assert!(!value.to_string().contains("explicit-0001"));
    Ok(())
}

#[tokio::test]
async fn a_failed_save_still_installs_the_session_and_reports_memory_with_a_note()
-> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    // The own directory is a regular file, so the save cannot land.
    let blocked = dir.path().join("blocked");
    std::fs::write(&blocked, "not a directory")?;
    let rig = Rig::start(
        Options::new(vec![identifier(), code(CODE)])
            .env("EERO_MCP_CONFIG_DIR", blocked.to_str().expect("utf-8")),
    )
    .await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;
    mount_account_for(&rig, LOGIN_TOKEN, 1).await;

    let result = rig.login(json!({})).await?;

    let value = structured(&result)?;
    assert_eq!(value["data"]["store"], "memory");
    let notes = value["data"]["notes"].as_array().expect("a note");
    assert!(
        notes[0]
            .as_str()
            .unwrap_or_default()
            .contains("only until the server stops")
    );
    assert_result_clean(&result);
    // The session works in the running server all the same.
    structured(&rig.get_account().await?)?;
    assert_eq!(std::fs::read_to_string(&blocked)?, "not a directory");
    Ok(())
}

// ===================== one login at a time =====================

#[tokio::test]
async fn a_second_login_while_one_waits_fails_at_once_and_the_first_still_completes()
-> anyhow::Result<()> {
    let rig = Arc::new(
        Rig::start(Options::new(vec![
            Reply::Hold(Box::new(identifier())),
            code(CODE),
        ]))
        .await?,
    );
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;

    // The first login waits on the identifier form.
    let first = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.login(json!({})).await })
    };
    rig.forms_arrived(1).await;

    let second = rig.login(json!({})).await?;
    let error = error_of(&second)?;
    assert_eq!(error["code"], "login_failed");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("already in progress")
    );
    assert_eq!(rig.shown().len(), 1, "the second call showed no form");
    assert!(targets_of(&rig.mock).await.is_empty());

    // The held form is answered and the first login finishes normally.
    rig.release.notify_one();
    let first = first.await??;
    assert_eq!(structured(&first)?["data"]["logged_in"], true);
    Ok(())
}

// ===================== timeouts, cancellation, progress =====================

#[tokio::test]
async fn a_form_nobody_answers_times_out_into_login_cancelled_and_frees_the_lock()
-> anyhow::Result<()> {
    let mut options = Options::new(vec![identifier(), Reply::Hold(Box::new(code(CODE)))]);
    // The same code path as the 10-minute wait, with a short timeout.
    options.form_timeout = Some(Duration::from_millis(300));
    let rig = Rig::start(options).await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;

    let result = rig.login(json!({})).await?;

    let error = error_of(&result)?;
    assert_eq!(error["code"], "login_cancelled");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("10 minutes")
    );
    assert!(!rig.own_file().exists());
    assert_eq!(targets_of(&rig.mock).await, ["POST /2.2/login"]);
    // The lock is free again: an invalid argument is answered as such, not as "in progress".
    let again = error_of(&rig.login(json!({"identifier": 5})).await?)?;
    assert_eq!(again["code"], "invalid_argument");
    Ok(())
}

#[tokio::test]
async fn cancelling_the_tool_call_during_the_code_form_frees_the_lock_and_sends_nothing_more()
-> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![
        identifier(),
        Reply::Hold(Box::new(code(CODE))),
    ]))
    .await?;
    // One start is expected; a verify or resend would hit the write tripwire.
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;

    let request = ClientRequest::CallToolRequest(CallToolRequest::new(
        CallToolRequestParams::new("login").with_arguments(object!({})),
    ));
    let handle = rig
        .client
        .peer()
        .send_cancellable_request(request, PeerRequestOptions::no_options())
        .await?;

    // The identifier form is answered at once; the code form is held open.
    rig.forms_arrived(2).await;
    assert_eq!(rig.shown().len(), 2);
    assert_eq!(targets_of(&rig.mock).await, ["POST /2.2/login"]);

    // The host gives up on the call.
    handle
        .cancel(Some("test: the host timed out".to_owned()))
        .await?;

    // The lock is released: a new call is not refused as "in progress". It fails on its invalid
    // argument, before anything is sent. Poll, because rmcp cancels the handler's token
    // asynchronously.
    let mut released = false;
    for _ in 0..100 {
        let probe = error_of(&rig.login(json!({"identifier": 5})).await?)?;
        if probe["code"] == "invalid_argument" {
            released = true;
            break;
        }
        assert!(
            probe["message"]
                .as_str()
                .unwrap_or_default()
                .contains("already in progress"),
            "{probe}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        released,
        "the login lock was never released after the cancellation"
    );

    // Nothing was saved, nothing was installed.
    assert!(!rig.own_file().exists());
    let read = error_of(&rig.get_account().await?)?;
    assert_eq!(read["code"], "authentication_required");

    // The held form is finally answered: rmcp discards the late answer, and nothing more is sent.
    rig.release.notify_one();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        targets_of(&rig.mock).await,
        ["POST /2.2/login"],
        "exactly the one start, no resend and no verify, also after the late answer"
    );
    assert!(!rig.own_file().exists());
    Ok(())
}

#[tokio::test]
async fn progress_notifications_with_fixed_text_go_out_while_a_form_is_open() -> anyhow::Result<()>
{
    let mut options = Options::new(vec![identifier(), Reply::Hold(Box::new(code(CODE)))]);
    options.progress_interval = Some(Duration::from_millis(100));
    let rig = Arc::new(Rig::start(options).await?);
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;

    let call = {
        let rig = Arc::clone(&rig);
        tokio::spawn(async move { rig.login(json!({})).await })
    };
    rig.forms_arrived(2).await;
    // The code form stays open for a while, so the periodic notifications fire.
    tokio::time::sleep(Duration::from_millis(450)).await;
    rig.release.notify_one();
    let result = call.await??;
    assert_eq!(structured(&result)?["data"]["logged_in"], true);

    let progress = rig.progress();
    let identifier_waits = progress
        .iter()
        .filter(|message| message.contains("account identifier"))
        .count();
    let code_waits = progress
        .iter()
        .filter(|message| message.contains("one-time code"))
        .count();
    assert_eq!(identifier_waits, 1, "{progress:?}");
    assert!(
        code_waits >= 3,
        "one as the form opens, then every interval: {progress:?}"
    );
    for message in &progress {
        assert_clean(message);
    }
    Ok(())
}

// ===================== the start budget =====================

/// Waits until the login lock is free again after a cancellation: a call with an invalid argument
/// is answered as such once the lock is free, and as "in progress" before (rmcp cancels the
/// handler's token asynchronously). The probe is refused before any request and takes nothing from
/// the start budget.
async fn wait_for_the_login_lock(rig: &Rig) -> anyhow::Result<()> {
    for _ in 0..100 {
        let probe = error_of(&rig.login(json!({"identifier": 5})).await?)?;
        if probe["code"] == "invalid_argument" {
            return Ok(());
        }
        assert!(
            probe["message"]
                .as_str()
                .unwrap_or_default()
                .contains("already in progress"),
            "{probe}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("the login lock was never released after the cancellation")
}

#[tokio::test]
async fn cancelled_calls_stop_sending_login_starts_once_the_budget_is_used_up() -> anyhow::Result<()>
{
    // Each call carries the identifier, so its start goes out at once; then the code form is held
    // open and the host gives up on the call. The lock is free again after each, but the starts
    // already made stay counted.
    let rig = Rig::start(Options::new(vec![
        Reply::Hold(Box::new(code(CODE))),
        Reply::Hold(Box::new(code(CODE))),
        Reply::Hold(Box::new(code(CODE))),
    ]))
    .await?;
    // Exactly three starts are expected; a fourth would hit the write tripwire.
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 3).await;

    for call in 1..=3usize {
        let request = ClientRequest::CallToolRequest(CallToolRequest::new(
            CallToolRequestParams::new("login").with_arguments(object!({"identifier": IDENTIFIER})),
        ));
        let handle = rig
            .client
            .peer()
            .send_cancellable_request(request, PeerRequestOptions::no_options())
            .await?;
        rig.forms_arrived(1).await;
        assert_eq!(
            targets_of(&rig.mock).await.len(),
            call,
            "start number {call}"
        );
        handle
            .cancel(Some("test: the host timed out".to_owned()))
            .await?;
        wait_for_the_login_lock(&rig).await?;
    }
    assert_eq!(rig.shown().len(), 3);

    // The budget is used up: the next calls answer at once with fixed text and the wait, show no
    // form and send nothing.
    for _ in 0..2 {
        let result = rig.login(json!({"identifier": IDENTIFIER})).await?;
        let error = error_of(&result)?;
        assert_eq!(error["code"], "rate_limited");
        let wait = error["retry_after_seconds"].as_u64().expect("a wait");
        assert!((1..=900).contains(&wait), "{error}");
        let message = error["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("3 in 15 minutes") && message.contains("Nothing was sent"),
            "{message}"
        );
        assert_result_clean(&result);
    }
    assert_eq!(rig.shown().len(), 3, "no further form");
    assert_eq!(
        targets_of(&rig.mock).await,
        ["POST /2.2/login", "POST /2.2/login", "POST /2.2/login"],
        "once the budget is used up no call sends a start"
    );
    // Nothing was ever saved or installed.
    assert!(!rig.own_file().exists());
    let read = error_of(&rig.get_account().await?)?;
    assert_eq!(read["code"], "authentication_required");
    Ok(())
}

#[tokio::test]
async fn the_restarts_of_a_call_use_the_budget_and_the_next_call_does_not_even_ask()
-> anyhow::Result<()> {
    // Three wrong codes are three starts: the whole budget.
    let rig = Rig::start(Options::new(vec![
        identifier(),
        code(CODE),
        code(CODE),
        code(CODE),
    ]))
    .await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 3).await;
    mount_verify_error(
        &rig.mock,
        LOGIN_TOKEN,
        CODE,
        401,
        Some("error.verification.invalid"),
        3,
    )
    .await;
    let first = error_of(&rig.login(json!({})).await?)?;
    assert_eq!(first["code"], "login_failed");
    assert_eq!(rig.shown().len(), 4);
    assert_eq!(targets_of(&rig.mock).await.len(), 6);

    // Without an identifier argument the identifier form would come first; the budget is checked
    // before it, so the user is not asked for an identifier for a login that cannot start.
    let second = error_of(&rig.login(json!({})).await?)?;
    assert_eq!(second["code"], "rate_limited");
    assert_eq!(rig.shown().len(), 4, "no identifier form");
    assert_eq!(targets_of(&rig.mock).await.len(), 6, "nothing was sent");
    Ok(())
}

// ===================== review fixes =====================

#[tokio::test]
async fn a_server_error_at_verification_is_the_generic_failure_not_a_refusal() -> anyhow::Result<()>
{
    let rig = Rig::start(Options::new(vec![identifier(), code(CODE), code(CODE)])).await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_error(&rig.mock, LOGIN_TOKEN, CODE, 500, None, 1).await;

    let result = rig.login(json!({})).await?;

    let error = error_of(&result)?;
    assert_eq!(error["code"], "login_failed");
    let message = error["message"].as_str().unwrap_or_default();
    assert_eq!(message, "The login failed. Nothing was saved.");
    assert!(!message.contains("refused"), "{message}");
    assert_result_clean(&result);
    assert_eq!(rig.shown().len(), 2, "no further code form");
    assert_eq!(targets_of(&rig.mock).await.len(), 2, "no restart");
    assert!(!rig.own_file().exists());
    Ok(())
}

#[tokio::test]
async fn a_zero_progress_interval_is_raised_instead_of_panicking_the_form_ticker()
-> anyhow::Result<()> {
    let mut options = Options::new(vec![identifier(), code(CODE)]);
    options.progress_interval = Some(Duration::ZERO);
    let rig = Rig::start(options).await?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;

    // A panicking handler task never answers: bound the wait so a regression fails, not hangs.
    let result = tokio::time::timeout(Duration::from_secs(30), rig.login(json!({}))).await??;

    assert_eq!(structured(&result)?["data"]["logged_in"], true);
    Ok(())
}

fn record(token: &str) -> String {
    format!(r#"{{"session_id":"{token}","schema_version":2}}"#)
}

const OLDER_SESSION: &str = "older-session-0001";

#[tokio::test]
async fn logging_in_again_signs_the_previous_session_out_after_installing_the_new_one()
-> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![identifier(), code(CODE)])).await?;
    std::fs::create_dir_all(rig.dir.path().join("cfg"))?;
    std::fs::write(rig.own_file(), record(OLDER_SESSION))?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;
    mount_logout(&rig.mock, OLDER_SESSION, 1).await;

    let result = rig.login(json!({})).await?;

    let value = structured(&result)?;
    assert_eq!(value["data"]["store"], "file");
    let notes = value["data"]["notes"].to_string();
    assert!(
        notes.contains("previous eero-mcp session was signed out"),
        "{notes}"
    );
    assert_result_clean(&result);
    assert!(!notes.contains(OLDER_SESSION));
    assert_eq!(
        targets_of(&rig.mock).await,
        [
            "POST /2.2/login",
            "POST /2.2/login/verify",
            "POST /2.2/logout"
        ]
    );
    assert!(std::fs::read_to_string(rig.own_file())?.contains(LOGIN_TOKEN));
    Ok(())
}

#[tokio::test]
async fn a_previous_session_the_environment_also_holds_is_not_signed_out() -> anyhow::Result<()> {
    let rig = Rig::start(
        Options::new(vec![identifier(), code(CODE)]).env("RUSTEERO_SESSION_TOKEN", OLDER_SESSION),
    )
    .await?;
    std::fs::create_dir_all(rig.dir.path().join("cfg"))?;
    std::fs::write(rig.own_file(), record(OLDER_SESSION))?;
    mount_start(&rig.mock, IDENTIFIER, LOGIN_TOKEN, 1).await;
    mount_verify_ok(&rig.mock, LOGIN_TOKEN, CODE, 1).await;

    let result = rig.login(json!({})).await?;

    let value = structured(&result)?;
    let notes = value["data"]["notes"].to_string();
    assert!(!notes.contains("signed out"), "{notes}");
    assert!(notes.contains("RUSTEERO_SESSION_TOKEN"), "{notes}");
    assert_eq!(
        targets_of(&rig.mock).await,
        ["POST /2.2/login", "POST /2.2/login/verify"],
        "no sign-out: the environment token is the same session"
    );
    Ok(())
}

// ===================== the pickup of a terminal login =====================

#[tokio::test]
async fn a_running_server_picks_up_a_terminal_login_on_its_next_call() -> anyhow::Result<()> {
    let rig = Rig::start(Options::new(vec![])).await?;

    // No credential anywhere: the read fails without a request.
    let before = error_of(&rig.get_account().await?)?;
    assert_eq!(before["code"], "authentication_required");
    assert!(targets_of(&rig.mock).await.is_empty());

    // A terminal login saves the session exactly as the subcommand does.
    let store = OwnStore::production(&rig.settings);
    save_session(
        &store,
        &rig.chain,
        &SecretString::from(LOGIN_TOKEN.to_owned()),
    )
    .await?;

    // The next call needs no restart and carries the new token.
    mount_account_for(&rig, LOGIN_TOKEN, 1).await;
    let account = structured(&rig.get_account().await?)?;
    assert_eq!(account["data"]["id"], "user-0001");
    assert_eq!(targets_of(&rig.mock).await, ["GET /2.2/account"]);
    Ok(())
}
