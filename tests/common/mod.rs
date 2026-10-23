//! Shared harness: wiremock -> rusteero `Client` -> eero-mcp server -> in-process rmcp client.
//!
//! This file is a *module*, not its own test binary: it lives at `tests/common/mod.rs` so cargo
//! never builds it standalone. Every test file pulls it in with `mod common;`.
//!
//! What [`Harness::start`] builds, and why it mirrors production:
//!
//! 1. a wiremock [`MockServer`] standing in for the eero cloud (one root serves both `/2.2` and
//!    `/2.3`), with the write tripwire mounted (any POST, PUT, PATCH or DELETE fails the test when
//!    the server drops). Every mock server in the test suite comes from [`mock_cloud`], so none can
//!    forget the tripwire;
//! 2. a rusteero `Client` from [`eero_mcp::client_builder`] (the very builder `main` uses: no
//!    credential store, one GET retry, default 60 s cache and timeouts) pointed at the mock, with
//!    the session token [`TEST_TOKEN`];
//! 3. the eero-mcp server built through the public constructor, with a fake credential resolver;
//! 4. an in-process rmcp client connected to the server over a tokio duplex stream.
//!
//! Test hosts never equal the production API host. Fixtures are synthetic only
//! (`network-0001`, `eero-0001`, `device-0001`, `profile-0001`, `aa:bb:cc:00:00:01`,
//! `user@example.com`) and live in `tests/fixtures/<group>/<name>.json`.

// Not every helper has a caller in every test binary that pulls this module in.
#![allow(dead_code)]

use std::path::PathBuf;

use anyhow::Context as _;
use eero_mcp::{EeroMcp, Resolver, client_builder};
use rmcp::model::{CallToolRequestParams, CallToolResult, JsonObject};
use rmcp::service::RunningService;
use rmcp::{RoleClient, ServiceExt as _};
use secrecy::SecretString;
use serde_json::Value;
use wiremock::matchers::{HeaderExactMatcher, any, header, method, path};
use wiremock::{Match, Mock, MockBuilder, MockServer, Request, ResponseTemplate};

/// The session token the harness Client starts with.
pub const TEST_TOKEN: &str = "test-token";

/// Matches `X-User-Token: test-token`, the primary credential.
#[must_use]
pub fn user_token_header() -> HeaderExactMatcher {
    user_token_header_for(TEST_TOKEN)
}

/// Matches `X-User-Token: <token>`.
#[must_use]
pub fn user_token_header_for(token: &str) -> HeaderExactMatcher {
    header("x-user-token", token)
}

/// Matches `Cookie: s=test-token`, the legacy credential rusteero sends alongside by default.
#[must_use]
pub fn session_cookie() -> HeaderExactMatcher {
    session_cookie_for(TEST_TOKEN)
}

/// Matches `Cookie: s=<token>`.
#[must_use]
pub fn session_cookie_for(token: &str) -> HeaderExactMatcher {
    header("cookie", format!("s={token}"))
}

/// Matches a request whose query string is exactly `expected`: the same name/value pairs, in any
/// order, and nothing else. wiremock's own `query_param` only checks that a pair is present, so an
/// unexpected parameter (a filter that should not be sent, a `timezone` sent when it was omitted)
/// would pass unnoticed.
#[derive(Debug, Clone)]
pub struct ExactQuery(Vec<(String, String)>);

impl ExactQuery {
    /// A matcher for exactly `pairs`; an empty slice means "no query string at all".
    #[must_use]
    pub fn new(pairs: &[(&str, &str)]) -> Self {
        let mut expected: Vec<(String, String)> = pairs
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        expected.sort();
        Self(expected)
    }
}

impl Match for ExactQuery {
    fn matches(&self, request: &Request) -> bool {
        let mut received: Vec<(String, String)> = request
            .url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        received.sort();
        received == self.0
    }
}

/// A GET mock for `route` that requires both credentials carrying `token` and **no query string**.
/// Finish it with `.respond_with(..)`, `.expect(n)` and `.mount(&h.mock)`.
#[must_use]
pub fn authed_get_as(route: &str, token: &str) -> MockBuilder {
    authed_get_with_as(route, token, &[])
}

/// As [`authed_get_as`], pinning the query to exactly `query` (any other parameter, or a missing
/// one, does not match).
#[must_use]
pub fn authed_get_with_as(route: &str, token: &str, query: &[(&str, &str)]) -> MockBuilder {
    Mock::given(method("GET"))
        .and(path(route))
        .and(user_token_header_for(token))
        .and(session_cookie_for(token))
        .and(ExactQuery::new(query))
}

/// A GET mock for `route` that requires both credentials carrying [`TEST_TOKEN`] and no query
/// string. Finish it with `.respond_with(..)`, `.expect(n)` and `.mount(&h.mock)`, or use
/// [`Harness::mount_get`].
#[must_use]
pub fn authed_get(route: &str) -> MockBuilder {
    authed_get_as(route, TEST_TOKEN)
}

/// As [`authed_get`], pinning the query to exactly `query`: every `(name, value)` must be sent with
/// exactly that value and nothing else may be sent. An optional parameter that must be absent is
/// simply left out of `query`.
#[must_use]
pub fn authed_get_with(route: &str, query: &[(&str, &str)]) -> MockBuilder {
    authed_get_with_as(route, TEST_TOKEN, query)
}

/// A 200 response carrying `body` (a fixture) as JSON.
#[must_use]
pub fn json_response(body: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_raw(body.to_owned(), "application/json")
}

/// A response with `status` carrying `body` as JSON.
#[must_use]
pub fn json_status(status: u16, body: &Value) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(body.to_string(), "application/json")
}

/// Any write verb fails the test when the `MockServer` drops. Lowest priority, so the one allowed
/// non-GET (rusteero's automatic `POST /2.2/login/refresh`) wins when a test mounts it.
pub async fn mount_write_tripwire(mock: &MockServer) {
    for verb in ["POST", "PUT", "PATCH", "DELETE"] {
        Mock::given(method(verb))
            .respond_with(ResponseTemplate::new(500))
            .with_priority(u8::MAX)
            .expect(0)
            .named(format!("write tripwire: {verb}"))
            .mount(mock)
            .await;
    }
}

/// A mock eero cloud with the write tripwire mounted. Start every `MockServer` of the test suite
/// through this function.
pub async fn mock_cloud() -> MockServer {
    let mock = MockServer::start().await;
    mount_write_tripwire(&mock).await;
    mock
}

/// The eero-mcp server over a Client built exactly as production builds it, pointed at `origin`.
pub async fn build_server(
    origin: &str,
    token: Option<&str>,
    resolver: Resolver,
) -> anyhow::Result<EeroMcp> {
    let token = token.map(|token| SecretString::from(token.to_owned()));
    let eero = client_builder(Some(origin), token.as_ref())
        .build()
        .await
        .context("building the rusteero client against the mock")?;
    Ok(EeroMcp::new(eero, resolver))
}

/// A mock cloud (write tripwire mounted) and a server wired to it, for tests that call the
/// server's building blocks directly instead of going through MCP.
pub async fn direct_server(resolver: Resolver) -> anyhow::Result<(MockServer, EeroMcp)> {
    let mock = mock_cloud().await;
    let server = build_server(&mock.uri(), Some(TEST_TOKEN), resolver).await?;
    Ok((mock, server))
}

/// The harness: mock cloud, server and in-process MCP client.
pub struct Harness {
    /// The mock eero cloud. Mount GET mocks on it; `.expect(n)` is verified when it drops.
    pub mock: MockServer,
    /// The in-process MCP client connected to the server.
    pub client: RunningService<RoleClient, ()>,
}

impl Harness {
    /// The default: the Client carries [`TEST_TOKEN`] and the credential re-read finds nothing.
    pub async fn start() -> anyhow::Result<Self> {
        Self::start_with(Resolver::fixed(None)).await
    }

    /// As [`Harness::start`] with a chosen fake credential resolver.
    pub async fn start_with(resolver: Resolver) -> anyhow::Result<Self> {
        Self::start_with_session(Some(TEST_TOKEN), resolver).await
    }

    /// As [`Harness::start`], but the Client starts with no session at all.
    pub async fn start_anonymous(resolver: Resolver) -> anyhow::Result<Self> {
        Self::start_with_session(None, resolver).await
    }

    /// The general constructor: the Client starts with `token` (or none).
    pub async fn start_with_session(
        token: Option<&str>,
        resolver: Resolver,
    ) -> anyhow::Result<Self> {
        Self::start_at(None, token, resolver).await
    }

    /// As [`Harness::start_with_session`], with the Client pointed at `origin` instead of the mock
    /// (for example a closed port, to provoke a connection failure).
    pub async fn start_at(
        origin: Option<&str>,
        token: Option<&str>,
        resolver: Resolver,
    ) -> anyhow::Result<Self> {
        let mock = mock_cloud().await;
        let origin = origin.map_or_else(|| mock.uri(), str::to_owned);
        let server = build_server(&origin, token, resolver).await?;

        let (server_io, client_io) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let running = server.serve(server_io).await?;
            running.waiting().await?;
            anyhow::Ok(())
        });
        let client = ().serve(client_io).await.context("connecting the MCP client")?;
        Ok(Self { mock, client })
    }

    /// The mock's origin, such as `http://127.0.0.1:41234`: the configured API origin.
    #[must_use]
    pub fn origin(&self) -> String {
        self.mock.uri()
    }

    /// Calls a tool and returns the raw MCP result.
    pub async fn call(&self, tool: &str, args: JsonObject) -> anyhow::Result<CallToolResult> {
        let params = CallToolRequestParams::new(tool.to_owned()).with_arguments(args);
        Ok(self.client.call_tool(params).await?)
    }

    /// Calls a tool with no arguments at all (the `arguments` member is omitted).
    pub async fn call_without_arguments(&self, tool: &str) -> anyhow::Result<CallToolResult> {
        Ok(self
            .client
            .call_tool(CallToolRequestParams::new(tool.to_owned()))
            .await?)
    }

    /// Calls a tool that must succeed and returns its parsed `structuredContent` object (checked
    /// to be mirrored by the single text block).
    pub async fn call_ok(&self, tool: &str, args: JsonObject) -> anyhow::Result<Value> {
        structured(&self.call(tool, args).await?)
    }

    /// Calls a tool that must fail in-band and returns the parsed `{"error": {...}}` object.
    pub async fn call_err(&self, tool: &str, args: JsonObject) -> anyhow::Result<Value> {
        error_json(&self.call(tool, args).await?)
    }

    /// Mounts `GET route` requiring both credentials and **no query string**, answering 200 with
    /// `body`, and expecting exactly `calls` requests (verified when the mock drops).
    pub async fn mount_get(&self, route: &str, body: &str, calls: u64) {
        self.mount_get_with(route, &[], body, calls).await;
    }

    /// As [`Harness::mount_get`], pinning the query to exactly `query` (see [`authed_get_with`]).
    pub async fn mount_get_with(
        &self,
        route: &str,
        query: &[(&str, &str)],
        body: &str,
        calls: u64,
    ) {
        authed_get_with(route, query)
            .respond_with(json_response(body))
            .expect(calls)
            .mount(&self.mock)
            .await;
    }

    /// Mounts the account's network list with exactly one network (`network-0001`), expecting
    /// `calls` requests: what default-network resolution reads.
    pub async fn mount_single_network(&self, calls: u64) {
        let body = serde_json::json!({
            "meta": {"code": 200, "server_time": "2026-01-01T00:00:15Z"},
            "data": [{
                "url": "/2.2/networks/network-0001",
                "name": "Example-Network"
            }]
        });
        authed_get("/2.2/networks")
            .respond_with(json_response(&body.to_string()))
            .expect(calls)
            .mount(&self.mock)
            .await;
    }

    /// A catch-all mock that fails the test when the mock drops if *any* request reached it:
    /// mount it first on a test whose arguments must be rejected before the wire.
    pub async fn expect_no_requests(&self) {
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .with_priority(u8::MAX)
            .expect(0)
            .named("no request may reach the wire")
            .mount(&self.mock)
            .await;
    }

    /// Every request the mock has received so far.
    pub async fn received(&self) -> Vec<Request> {
        self.mock.received_requests().await.unwrap_or_default()
    }

    /// Every request received so far as `METHOD /path?query`, in arrival order: pins the exact
    /// path and query of what went over the wire.
    pub async fn targets(&self) -> Vec<String> {
        self.received()
            .await
            .iter()
            .map(|request| match request.url.query() {
                Some(query) => format!("{} {}?{query}", request.method, request.url.path()),
                None => format!("{} {}", request.method, request.url.path()),
            })
            .collect()
    }

    /// Asserts, right now, that no request has reached the mock.
    pub async fn assert_no_requests(&self) {
        let received = self.received().await;
        assert!(
            received.is_empty(),
            "expected zero requests, got {}: {:?}",
            received.len(),
            received
                .iter()
                .map(|r| format!("{} {}", r.method, r.url.path()))
                .collect::<Vec<_>>()
        );
    }
}

/// `structuredContent` of a successful result, checked to be mirrored by the single text block.
pub fn structured(result: &CallToolResult) -> anyhow::Result<Value> {
    anyhow::ensure!(
        result.is_error == Some(false),
        "expected success, got {result:?}"
    );
    let value = result
        .structured_content
        .clone()
        .context("no structuredContent")?;
    anyhow::ensure!(
        result.content.len() == 1,
        "exactly one content block, got {}",
        result.content.len()
    );
    let text = result.content[0]
        .as_text()
        .context("content block is not text")?;
    anyhow::ensure!(
        serde_json::from_str::<Value>(&text.text)? == value,
        "the text block must mirror structuredContent"
    );
    Ok(value)
}

/// The `{"error": {...}}` object of a tool error (no `structuredContent`).
pub fn error_json(result: &CallToolResult) -> anyhow::Result<Value> {
    anyhow::ensure!(
        result.is_error == Some(true),
        "expected isError, got {result:?}"
    );
    anyhow::ensure!(
        result.structured_content.is_none(),
        "errors carry no structuredContent"
    );
    anyhow::ensure!(result.content.len() == 1, "exactly one content block");
    let text = result
        .content
        .first()
        .and_then(|block| block.as_text())
        .context("no text block")?;
    let value: Value = serde_json::from_str(&text.text)?;
    anyhow::ensure!(
        value.as_object().map(serde_json::Map::len) == Some(1) && value.get("error").is_some(),
        "the only member is `error`: {value}"
    );
    Ok(value)
}

/// `name` in group `group`, resolved against `tests/fixtures/<group>/<name>.json` regardless of the
/// working directory.
#[must_use]
pub fn fixture(group: &str, name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(group)
        .join(format!("{name}.json"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {}: {e}", path.display()))
}

/// [`fixture`] parsed as JSON.
#[must_use]
pub fn fixture_json(group: &str, name: &str) -> Value {
    serde_json::from_str(&fixture(group, name))
        .unwrap_or_else(|e| panic!("fixture {group}/{name} is not JSON: {e}"))
}
