//! Error mapping end to end, through a tool: every row of the error-mapping table that a
//! mocked HTTP response can provoke, the fixed texts (no URL, path, host or token ever reaches the
//! client), the single GET retry, and the credential re-read and retry.
//!
//! The one row the mock cannot produce is a future rusteero variant (the wildcard arm), which the
//! `errors.rs` unit tests cover. The timeout row takes about 22 s of real time and does not pause
//! the clock: rusteero runs its timers on tokio's, and a paused clock auto-advances past them.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{Harness, TEST_TOKEN, authed_get, authed_get_as, fixture, json_response, json_status};
use eero_mcp::Resolver;
use rmcp::object;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, ResponseTemplate};

const ROUTE: &str = "/2.2/networks/network-0001/guestnetwork";
const NETWORK_ARGS: fn() -> rmcp::model::JsonObject = || object!({"network_id": "network-0001"});

/// The tool every case goes through: one explicit-network read.
const TOOL: &str = "get_guest_network";

fn error_body(code: &str) -> Value {
    json!({"meta": {"code": 0, "error": code}, "data": {"password": "hunter2"}})
}

/// Mounts one GET answering `template`, expecting exactly `calls` requests.
async fn mount(h: &Harness, template: ResponseTemplate, calls: u64) {
    authed_get(ROUTE)
        .respond_with(template)
        .expect(calls)
        .mount(&h.mock)
        .await;
}

/// Calls the tool and returns the inner `error` object.
async fn failure(h: &Harness) -> anyhow::Result<Value> {
    let out = h.call_err(TOOL, NETWORK_ARGS()).await?;
    Ok(out["error"].clone())
}

/// No rusteero text, URL, path, host, id, token or upstream body may reach the client.
fn assert_clean(error: &Value) {
    let rendered = error.to_string();
    for leak in [
        "127.0.0.1",
        "localhost",
        "network-0001",
        "/2.2/",
        "guestnetwork",
        "hunter2",
        TEST_TOKEN,
        "evil.example",
        "http://",
        "https://",
    ] {
        assert!(!rendered.contains(leak), "{leak:?} leaked into {rendered}");
    }
}

// ===================== authentication =====================

#[tokio::test]
async fn status_401_is_authentication_required_with_status_and_code() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(
        &h,
        json_status(401, &error_body("error.session.expired")),
        1,
    )
    .await;

    let error = failure(&h).await?;

    assert_eq!(error["code"], "authentication_required");
    assert_eq!(error["upstream_status"], 401);
    assert_eq!(error["upstream_code"], "error.session.expired");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("eeroctl")
    );
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn status_401_without_a_code_is_still_authentication_required() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(&h, ResponseTemplate::new(401), 1).await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "authentication_required");
    assert_eq!(error["upstream_status"], 401);
    assert!(error.get("upstream_code").is_none());
    Ok(())
}

#[tokio::test]
async fn a_401_is_authentication_even_when_its_meta_error_names_another_group() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    mount(
        &h,
        json_status(401, &error_body("error.premium.user_not_subscribed")),
        1,
    )
    .await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "authentication_required");
    Ok(())
}

// ===================== access, premium, feature, client =====================

#[tokio::test]
async fn status_403_with_access_denied_is_access_denied() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(&h, json_status(403, &error_body("error.access.denied")), 1).await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "access_denied");
    assert_eq!(error["upstream_status"], 403);
    assert_eq!(error["upstream_code"], "error.access.denied");
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn a_plain_403_is_an_upstream_error_with_status_403() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(
        &h,
        json_status(403, &json!({"meta": {"code": 403}, "data": {}})),
        1,
    )
    .await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "upstream_error");
    assert_eq!(error["upstream_status"], 403);
    assert_eq!(error["message"], "The eero cloud API returned an error.");
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn status_404_is_not_found() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(&h, ResponseTemplate::new(404), 1).await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "not_found");
    assert_eq!(error["upstream_status"], 404);
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn a_premium_meta_error_on_an_error_status_is_premium_required() -> anyhow::Result<()> {
    for status in [400, 403, 404] {
        let h = Harness::start().await?;
        mount(
            &h,
            json_status(status, &error_body("error.premium.user_not_subscribed")),
            1,
        )
        .await;
        let error = failure(&h).await?;
        assert_eq!(error["code"], "premium_required", "status {status}");
        assert_eq!(error["upstream_status"], u64::from(status));
        assert_eq!(error["upstream_code"], "error.premium.user_not_subscribed");
        assert_clean(&error);
    }
    Ok(())
}

#[tokio::test]
async fn a_feature_unavailable_meta_error_on_an_error_status_is_feature_unavailable()
-> anyhow::Result<()> {
    for status in [400, 404] {
        let h = Harness::start().await?;
        mount(
            &h,
            json_status(status, &error_body("error.eero.offline")),
            1,
        )
        .await;
        let error = failure(&h).await?;
        assert_eq!(error["code"], "feature_unavailable", "status {status}");
        assert_eq!(error["upstream_code"], "error.eero.offline");
        assert_clean(&error);
    }
    Ok(())
}

#[tokio::test]
async fn a_client_blocked_meta_error_is_client_blocked() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(
        &h,
        json_status(400, &error_body("error.app.version.blocked")),
        1,
    )
    .await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "client_blocked");
    assert_eq!(error["upstream_code"], "error.app.version.blocked");
    Ok(())
}

#[tokio::test]
async fn a_2xx_with_a_premium_meta_error_is_still_a_success() -> anyhow::Result<()> {
    // rusteero classifies meta.error only on error statuses.
    let h = Harness::start().await?;
    mount(
        &h,
        json_status(
            200,
            &json!({"meta": {"code": 200, "error": "error.premium.user_not_subscribed"}, "data": {"enabled": false}}),
        ),
        1,
    )
    .await;
    let out = h.call_ok(TOOL, NETWORK_ARGS()).await?;
    assert_eq!(out["data"], json!({"enabled": false}));
    Ok(())
}

// ===================== rate limit =====================

#[tokio::test]
async fn status_429_with_retry_after_is_rate_limited_and_never_retried() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(
        &h,
        json_status(429, &error_body("error.rate.limit")).insert_header("retry-after", "30"),
        1,
    )
    .await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "rate_limited");
    assert_eq!(error["retry_after_seconds"], 30);
    assert_eq!(error["upstream_status"], 429);
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn status_429_without_retry_after_has_no_retry_member() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(&h, ResponseTemplate::new(429), 1).await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "rate_limited");
    assert!(error.get("retry_after_seconds").is_none());
    Ok(())
}

// ===================== validation from eero =====================

#[tokio::test]
async fn a_400_with_a_validation_code_is_invalid_argument_without_a_field() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(&h, json_status(400, &error_body("error.form.errors")), 1).await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "invalid_argument");
    assert!(
        error.get("field").is_none(),
        "an upstream 400 names no parameter"
    );
    assert_eq!(error["upstream_code"], "error.form.errors");
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn a_400_without_a_validation_code_is_an_upstream_error() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(&h, json_status(400, &error_body("error.something.new")), 1).await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "upstream_error");
    assert_eq!(error["upstream_status"], 400);
    assert_eq!(error["upstream_code"], "error.something.new");
    Ok(())
}

// ===================== 5xx, redirects, bad bodies =====================

#[tokio::test]
async fn status_500_is_retried_once_then_upstream_error() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // Two requests because of the single GET retry.
    mount(&h, json_status(500, &error_body("error.internal")), 2).await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "upstream_error");
    assert_eq!(error["upstream_status"], 500);
    assert_eq!(error["message"], "The eero cloud API returned an error.");
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn a_5xx_followed_by_a_success_is_a_success() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    authed_get(ROUTE)
        .respond_with(ResponseTemplate::new(503))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&h.mock)
        .await;
    authed_get(ROUTE)
        .respond_with(json_response(&fixture("account", "guest_network")))
        .with_priority(2)
        .expect(1)
        .mount(&h.mock)
        .await;
    let out = h.call_ok(TOOL, NETWORK_ARGS()).await?;
    assert_eq!(out["data"]["enabled"], true);
    Ok(())
}

#[tokio::test]
async fn a_redirect_is_refused_with_fixed_text_carrying_no_path_or_host() -> anyhow::Result<()> {
    for status in [301, 302, 307] {
        let h = Harness::start().await?;
        mount(
            &h,
            ResponseTemplate::new(status).insert_header(
                "location",
                "https://evil.example/2.2/networks/network-0001/guestnetwork?secret=1",
            ),
            1,
        )
        .await;
        let error = failure(&h).await?;
        assert_eq!(error["code"], "upstream_error", "{status}");
        assert_eq!(error["upstream_status"], u64::from(status));
        assert_eq!(
            error["message"],
            "The eero cloud API answered with a redirect, which is refused."
        );
        assert_clean(&error);
        // The redirect target is never contacted: only the one mock saw a request.
        assert_eq!(h.targets().await, [format!("GET {ROUTE}")]);
    }
    Ok(())
}

#[tokio::test]
async fn a_2xx_body_that_is_not_a_json_object_is_an_upstream_error() -> anyhow::Result<()> {
    for body in [
        "[1,2,3]",
        "\"text\"",
        "42",
        "null",
        "true",
        "not json at all",
        "{\"data\": ",
    ] {
        let h = Harness::start().await?;
        mount(
            &h,
            ResponseTemplate::new(200).set_body_raw(body.to_owned(), "application/json"),
            1,
        )
        .await;
        let error = failure(&h).await?;
        assert_eq!(error["code"], "upstream_error", "{body:?}");
        assert_eq!(error["upstream_status"], 200, "{body:?}");
        assert_eq!(
            error["message"], "The eero cloud API returned an unexpected response.",
            "{body:?}"
        );
        assert_clean(&error);
    }
    Ok(())
}

#[tokio::test]
async fn a_2xx_body_that_is_not_utf8_or_is_over_the_size_cap_is_an_upstream_error()
-> anyhow::Result<()> {
    /// rusteero's `MAX_RESPONSE_BYTES` (10 MiB) plus one byte.
    const OVER_THE_CAP: usize = 10 * 1024 * 1024 + 1;

    for (label, body) in [
        ("not utf-8", vec![0xff, 0xfe, 0xfd]),
        ("over the size cap", vec![b' '; OVER_THE_CAP]),
    ] {
        let h = Harness::start().await?;
        mount(&h, ResponseTemplate::new(200).set_body_bytes(body), 1).await;
        let error = failure(&h).await?;
        assert_eq!(error["code"], "upstream_error", "{label}");
        assert_eq!(error["upstream_status"], 200, "{label}");
        assert_eq!(
            error["message"], "The eero cloud API returned an unexpected response.",
            "{label}"
        );
        assert_clean(&error);
    }
    Ok(())
}

#[tokio::test]
async fn an_empty_2xx_body_is_an_empty_envelope_not_an_error() -> anyhow::Result<()> {
    // rusteero treats an empty or whitespace-only 2xx body (and a 204) as an empty envelope.
    for template in [
        ResponseTemplate::new(200).set_body_string("  \n"),
        ResponseTemplate::new(204),
    ] {
        let h = Harness::start().await?;
        mount(&h, template, 1).await;
        let out = h.call_ok(TOOL, NETWORK_ARGS()).await?;
        assert_eq!(out["data"], Value::Null);
        assert_eq!(out["network_id"], "network-0001");
    }
    Ok(())
}

// ===================== timeout =====================

#[tokio::test]
async fn a_response_slower_than_the_read_timeout_is_timeout() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // rusteero gives a response 10 s to start. Two requests: the single GET retry also times
    // out. About 22 s of real time.
    mount(
        &h,
        json_response(&fixture("account", "guest_network")).set_delay(Duration::from_secs(11)),
        2,
    )
    .await;

    let error = failure(&h).await?;

    assert_eq!(error["code"], "timeout");
    assert_eq!(
        error["message"],
        "The eero cloud API did not answer in time."
    );
    assert!(error.get("upstream_status").is_none());
    assert_clean(&error);
    Ok(())
}

// ===================== network failure =====================

#[tokio::test]
async fn a_refused_connection_is_network_error_with_fixed_text_and_no_url() -> anyhow::Result<()> {
    // A closed port: bind an ephemeral port, then release it.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.local_addr()?.port()
    };
    let closed = format!("http://127.0.0.1:{port}");
    let h = Harness::start_at(Some(&closed), Some(TEST_TOKEN), Resolver::fixed(None)).await?;

    let error = failure(&h).await?;

    assert_eq!(error["code"], "network_error");
    assert!(error.get("upstream_status").is_none());
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.starts_with("Could not reach the eero cloud API"),
        "{message}"
    );
    assert!(
        !message.contains(closed.trim_start_matches("http://")),
        "{message}"
    );
    assert_clean(&error);
    let rendered = error.to_string();
    assert!(!rendered.contains("tcp"), "{rendered}");
    assert!(!rendered.contains("error sending request"), "{rendered}");
    Ok(())
}

// ===================== local validation is not an upstream error =====================

#[tokio::test]
async fn local_validation_never_reaches_the_wire() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    let err = h
        .call_err(TOOL, object!({"network_id": "../network-0001"}))
        .await?;
    assert_eq!(err["error"]["code"], "invalid_argument");
    assert!(err["error"].get("upstream_status").is_none());
    h.assert_no_requests().await;
    Ok(())
}

// ===================== credential re-read =====================

/// A resolver that counts its re-reads and yields `token`.
fn counting_resolver(token: Option<&'static str>) -> (Resolver, Arc<AtomicUsize>) {
    let reads = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reads);
    let resolver = Resolver::from_fn(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        token.map(str::to_owned)
    });
    (resolver, reads)
}

/// A GET on `ROUTE` that only matches requests carrying `token` on both credentials.
fn authed_with(token: &str) -> wiremock::MockBuilder {
    authed_get_as(ROUTE, token)
}

#[tokio::test]
async fn a_401_then_a_new_token_from_the_resolver_retries_once_with_it() -> anyhow::Result<()> {
    let (resolver, reads) = counting_resolver(Some("token-b"));
    let h = Harness::start_with(resolver).await?;
    authed_with(TEST_TOKEN)
        .respond_with(json_status(401, &error_body("error.session.expired")))
        .expect(1)
        .mount(&h.mock)
        .await;
    // Two requests with the new token: the retry, then the later call below.
    authed_with("token-b")
        .respond_with(json_response(&fixture("account", "guest_network")))
        .expect(2)
        .mount(&h.mock)
        .await;

    let out = h.call_ok(TOOL, NETWORK_ARGS()).await?;

    assert_eq!(out["data"]["enabled"], true);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    // The new token is installed: a later call carries it with no further 401 and no re-read.
    h.call_ok(TOOL, NETWORK_ARGS()).await?;
    assert_eq!(reads.load(Ordering::SeqCst), 1, "no second re-read");
    Ok(())
}

#[tokio::test]
async fn the_same_token_after_a_401_is_authentication_required_without_a_retry()
-> anyhow::Result<()> {
    let (resolver, reads) = counting_resolver(Some(TEST_TOKEN));
    let h = Harness::start_with(resolver).await?;
    mount(
        &h,
        json_status(401, &error_body("error.session.revoked")),
        1,
    )
    .await;

    let error = failure(&h).await?;

    assert_eq!(error["code"], "authentication_required");
    assert_eq!(error["upstream_status"], 401);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn a_credential_found_by_the_reread_is_never_reported_as_missing() -> anyhow::Result<()> {
    // The sources hold the token that just failed, and the 401 carries no eero error code.
    let (resolver, reads) = counting_resolver(Some(TEST_TOKEN));
    let h = Harness::start_with(resolver).await?;
    mount(&h, ResponseTemplate::new(401), 1).await;

    let error = failure(&h).await?;

    assert_eq!(error["code"], "authentication_required");
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("has expired, is invalid or was revoked"),
        "{message}"
    );
    assert!(!message.contains("No eero credential"), "{message}");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn nothing_found_by_the_reread_is_authentication_required_without_a_retry()
-> anyhow::Result<()> {
    let (resolver, reads) = counting_resolver(None);
    let h = Harness::start_with(resolver).await?;
    mount(&h, ResponseTemplate::new(401), 1).await;
    let error = failure(&h).await?;
    assert_eq!(error["code"], "authentication_required");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn the_retry_outcome_is_final_and_triggers_no_second_reread() -> anyhow::Result<()> {
    let (resolver, reads) = counting_resolver(Some("token-b"));
    let h = Harness::start_with(resolver).await?;
    authed_with(TEST_TOKEN)
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&h.mock)
        .await;
    authed_with("token-b")
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&h.mock)
        .await;

    let error = failure(&h).await?;

    assert_eq!(error["code"], "authentication_required");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn no_credentials_at_all_fails_before_any_request() -> anyhow::Result<()> {
    let (resolver, reads) = counting_resolver(None);
    let h = Harness::start_anonymous(resolver).await?;
    h.expect_no_requests().await;

    let error = failure(&h).await?;

    assert_eq!(error["code"], "authentication_required");
    let message = error["message"].as_str().unwrap_or_default();
    assert!(message.contains("No eero credential"), "{message}");
    assert!(error.get("upstream_status").is_none(), "nothing was sent");
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "the sources are re-read once"
    );
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_credential_that_appears_later_is_picked_up_without_a_restart() -> anyhow::Result<()> {
    // The server started with no credential; the user logs in afterwards.
    let (resolver, reads) = counting_resolver(Some("token-late"));
    let h = Harness::start_anonymous(resolver).await?;
    authed_with("token-late")
        .respond_with(json_response(&fixture("account", "guest_network")))
        .expect(1)
        .mount(&h.mock)
        .await;

    let out = h.call_ok(TOOL, NETWORK_ARGS()).await?;

    assert_eq!(out["data"]["name"], "Example-Network Guest");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn a_changed_token_reaches_the_default_network_lookup_too() -> anyhow::Result<()> {
    // The network-list read goes through the same call path, so it gets the same re-read.
    let (resolver, reads) = counting_resolver(Some("token-b"));
    let h = Harness::start_with(resolver).await?;
    authed_get_as("/2.2/networks", TEST_TOKEN)
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&h.mock)
        .await;
    authed_get_as("/2.2/networks", "token-b")
        .respond_with(json_response(&fixture("account", "networks_one")))
        .expect(1)
        .mount(&h.mock)
        .await;
    authed_with("token-b")
        .respond_with(json_response(&fixture("account", "guest_network")))
        .expect(1)
        .mount(&h.mock)
        .await;

    let out = h.call_ok(TOOL, object!({})).await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn concurrent_authentication_failures_install_the_new_token_once() -> anyhow::Result<()> {
    let (resolver, reads) = counting_resolver(Some("token-b"));
    let h = Harness::start_with(resolver).await?;
    authed_with(TEST_TOKEN)
        .respond_with(ResponseTemplate::new(401))
        .mount(&h.mock)
        .await;
    authed_with("token-b")
        .respond_with(json_response(&fixture("account", "guest_network")))
        .expect(4)
        .mount(&h.mock)
        .await;

    // Four parallel calls fail with the old token, one wins the re-read, all four end up on the
    // new token.
    let peer = h.client.peer().clone();
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let peer = peer.clone();
        calls.spawn(async move {
            peer.call_tool(
                rmcp::model::CallToolRequestParams::new(TOOL).with_arguments(NETWORK_ARGS()),
            )
            .await
        });
    }
    while let Some(joined) = calls.join_next().await {
        assert_eq!(joined??.is_error, Some(false));
    }
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "one re-read installs the token; the other calls waiting on the lock reuse it"
    );
    Ok(())
}

// ===================== the one allowed non-GET: rusteero's session refresh =====================

#[tokio::test]
async fn a_401_with_a_refresh_code_posts_the_refresh_and_replays_the_get() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    authed_get(ROUTE)
        .respond_with(json_status(401, &error_body("error.session.refresh")))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&h.mock)
        .await;
    authed_get(ROUTE)
        .respond_with(json_response(&fixture("account", "guest_network")))
        .with_priority(2)
        .expect(1)
        .mount(&h.mock)
        .await;
    // Outranks the write tripwire (default priority 5 beats 255), so this single POST is allowed.
    Mock::given(method("POST"))
        .and(path("/2.2/login/refresh"))
        .and(header("x-user-token", TEST_TOKEN))
        .respond_with(json_status(
            200,
            &json!({"meta": {"code": 200}, "data": {}}),
        ))
        .expect(1)
        .mount(&h.mock)
        .await;

    let out = h.call_ok(TOOL, NETWORK_ARGS()).await?;

    assert_eq!(out["data"]["enabled"], true);
    assert_eq!(
        h.targets().await,
        [
            format!("GET {ROUTE}"),
            "POST /2.2/login/refresh".to_owned(),
            format!("GET {ROUTE}")
        ]
    );
    Ok(())
}

// ===================== session refresh outcomes =====================

/// `GET ROUTE` for `token`: first a 401 asking for a session refresh, then the guest network.
async fn mount_refresh_then_success(h: &Harness, token: &str, successes: u64) {
    authed_get_as(ROUTE, token)
        .respond_with(json_status(401, &error_body("error.session.refresh")))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&h.mock)
        .await;
    authed_get_as(ROUTE, token)
        .respond_with(json_response(&fixture("account", "guest_network")))
        .with_priority(2)
        .expect(successes)
        .mount(&h.mock)
        .await;
}

/// The one allowed non-GET, answering `template`. It outranks the write tripwire.
async fn mount_refresh_post(h: &Harness, template: ResponseTemplate, calls: u64) {
    Mock::given(method("POST"))
        .and(path("/2.2/login/refresh"))
        .and(header("x-user-token", TEST_TOKEN))
        .respond_with(template)
        .expect(calls)
        .mount(&h.mock)
        .await;
}

#[tokio::test]
async fn a_terminal_refresh_failure_clears_the_session_and_the_next_call_reinstalls_the_credential()
-> anyhow::Result<()> {
    // The refresh POST is refused with a session error: rusteero clears its in-memory session (no
    // store is attached, so nothing else). The call that saw it fails; the re-read finds the very
    // token that was just refused, so it is not retried.
    let (resolver, reads) = counting_resolver(Some(TEST_TOKEN));
    let h = Harness::start_with(resolver).await?;
    mount_refresh_then_success(&h, TEST_TOKEN, 1).await;
    mount_refresh_post(
        &h,
        json_status(401, &error_body("error.session.invalid")),
        1,
    )
    .await;

    let error = failure(&h).await?;

    assert_eq!(error["code"], "authentication_required");
    assert_eq!(error["upstream_status"], 401);
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("expired, is invalid or was revoked"),
        "{message}"
    );
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert_clean(&error);

    // The Client has no session now. The next call must compare against that (no token in use),
    // not against a remembered copy: the re-read finds the configured token, installs it, and the
    // read goes through.
    let out = h.call_ok(TOOL, NETWORK_ARGS()).await?;
    assert_eq!(out["data"]["enabled"], true);
    assert_eq!(reads.load(Ordering::SeqCst), 2, "one more re-read");
    assert_eq!(
        h.targets().await,
        [
            format!("GET {ROUTE}"),
            "POST /2.2/login/refresh".to_owned(),
            format!("GET {ROUTE}")
        ],
        "the second call sent nothing until the credential was reinstalled"
    );
    Ok(())
}

#[tokio::test]
async fn a_retained_refresh_failure_keeps_the_session_and_enters_the_reread_path()
-> anyhow::Result<()> {
    // Authentication errors in the verification and session-refresh groups, and any non-network
    // failure of the POST, keep the session: the original 401 comes back and the re-read sees
    // the same token.
    let outcomes = [
        (
            "verification group",
            json_status(401, &error_body("error.verification.required")),
        ),
        (
            "session-refresh group",
            json_status(401, &error_body("error.session.refresh")),
        ),
        ("server error", ResponseTemplate::new(500)),
        (
            "forbidden",
            json_status(403, &error_body("error.access.denied")),
        ),
    ];
    for (label, template) in outcomes {
        let (resolver, reads) = counting_resolver(Some(TEST_TOKEN));
        let h = Harness::start_with(resolver).await?;
        // Both calls send their GET (the session was kept) and both refresh.
        authed_get_as(ROUTE, TEST_TOKEN)
            .respond_with(json_status(401, &error_body("error.session.refresh")))
            .expect(2)
            .mount(&h.mock)
            .await;
        mount_refresh_post(&h, template, 2).await;

        for call in 1..=2 {
            let error = failure(&h).await?;
            assert_eq!(error["code"], "authentication_required", "{label} #{call}");
            assert_eq!(error["upstream_status"], 401, "{label} #{call}");
            assert_clean(&error);
        }
        assert_eq!(
            reads.load(Ordering::SeqCst),
            2,
            "{label}: one re-read per call"
        );
    }
    Ok(())
}

/// A bare HTTP server for the one case wiremock cannot produce, a connection that drops. It answers
/// the first request with a 401 asking for a session refresh and hangs up on everything after it,
/// so the refresh POST fails at the network level. Returns its origin and a request counter.
async fn refresh_then_hang_up() -> anyhow::Result<(String, Arc<AtomicUsize>)> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let origin = format!("http://{}", listener.local_addr()?);
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let body = json!({"meta": {"code": 401, "error": "error.session.refresh"}});
                let body = body.to_string();
                let mut buffer = vec![0_u8; 16 * 1024];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                    if counter.fetch_add(1, Ordering::SeqCst) > 0 {
                        return; // hang up: the refresh POST never gets an answer
                    }
                    let response = format!(
                        "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    if socket.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Ok((origin, requests))
}

#[tokio::test]
async fn a_network_failure_of_the_refresh_post_is_a_network_error_not_a_reread()
-> anyhow::Result<()> {
    let (origin, requests) = refresh_then_hang_up().await?;
    let (resolver, reads) = counting_resolver(Some("token-b"));
    let h = Harness::start_at(Some(&origin), Some(TEST_TOKEN), resolver).await?;

    let error = failure(&h).await?;

    // The original 401 is dropped: the caller learns the cloud could not be reached, and the
    // credentials were never questioned.
    assert_eq!(error["code"], "network_error", "{error}");
    assert!(error.get("upstream_status").is_none());
    assert_eq!(reads.load(Ordering::SeqCst), 0, "no re-read");
    assert!(
        requests.load(Ordering::SeqCst) >= 2,
        "the GET and the POST were attempted"
    );
    assert_clean(&error);
    h.assert_no_requests().await; // the wiremock server was never the origin
    Ok(())
}

// ===================== rate limit on other statuses =====================

#[tokio::test]
async fn error_rate_limit_on_a_non_429_error_status_is_rate_limited() -> anyhow::Result<()> {
    for status in [400, 403, 404] {
        let h = Harness::start().await?;
        mount(&h, json_status(status, &error_body("error.rate.limit")), 1).await;
        let error = failure(&h).await?;
        assert_eq!(error["code"], "rate_limited", "status {status}");
        assert_eq!(error["upstream_status"], u64::from(status));
        assert_eq!(error["upstream_code"], "error.rate.limit");
        assert_clean(&error);
    }
    Ok(())
}

// ===================== the cache never outlives the credential =====================

#[tokio::test]
async fn a_new_credential_clears_the_cache_so_nothing_crosses_accounts() -> anyhow::Result<()> {
    let (resolver, reads) = counting_resolver(Some("token-b"));
    let h = Harness::start_with(resolver).await?;
    let account = |owner: &str| {
        json!({
            "meta": {"code": 200, "server_time": "2026-01-01T00:00:00Z"},
            "data": {"id": "user-0001", "name": owner}
        })
        .to_string()
    };

    // 1. Under the first token, get_account is cached: one request serves two calls.
    authed_get_as("/2.2/account", TEST_TOKEN)
        .respond_with(json_response(&account("Owner A")))
        .expect(1)
        .mount(&h.mock)
        .await;
    assert_eq!(
        h.call_ok("get_account", object!({})).await?["data"]["name"],
        "Owner A"
    );
    assert_eq!(
        h.call_ok("get_account", object!({})).await?["data"]["name"],
        "Owner A"
    );

    // 2. Another tool is refused; the re-read installs the second token and the call succeeds.
    authed_with(TEST_TOKEN)
        .respond_with(ResponseTemplate::new(401))
        .expect(1)
        .mount(&h.mock)
        .await;
    authed_with("token-b")
        .respond_with(json_response(&fixture("account", "guest_network")))
        .expect(1)
        .mount(&h.mock)
        .await;
    h.call_ok(TOOL, NETWORK_ARGS()).await?;
    assert_eq!(reads.load(Ordering::SeqCst), 1);

    // 3. The account read must go back to the wire under the new token: data cached for the old
    //    account must not be served to the new one.
    authed_get_as("/2.2/account", "token-b")
        .respond_with(json_response(&account("Owner B")))
        .expect(1)
        .mount(&h.mock)
        .await;
    let out = h.call_ok("get_account", object!({})).await?;
    assert_eq!(
        out["data"]["name"], "Owner B",
        "the cache was cleared by the new token"
    );
    Ok(())
}
