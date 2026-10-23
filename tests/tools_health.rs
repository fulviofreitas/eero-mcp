//! Pins the health-group tools (19 to 25): the listing and annotations, the input schemas, the
//! exact GET path and query rusteero sends (including its own query names), both credentials, the
//! output members, the 24-hour default window of `get_channel_utilization`, redaction,
//! default-network resolution, every validation branch (always before any request) and the error
//! mapping of upstream failures.

mod common;

use std::collections::BTreeMap;

use common::{Harness, fixture, fixture_json, json_response, json_status};
use eero_mcp::params::Band;
use jiff::Timestamp;
use rmcp::model::{JsonObject, Tool};
use rmcp::object;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request, ResponseTemplate};

const GROUP: &str = "health";
const NETWORK: &str = "/2.2/networks/network-0001";
const REDACTED: &str = "[REDACTED]";

/// Every health tool with the path suffix of its read and its fixture.
const HEALTH_TOOLS: [(&str, &str, &str); 7] = [
    ("list_speed_tests", "/speedtest", "speed_tests"),
    ("get_diagnostics", "/diagnostics", "diagnostics"),
    ("get_firmware_updates", "/updates", "updates"),
    (
        "get_channel_utilization",
        "/channel_utilization",
        "channel_utilization",
    ),
    ("get_network_scan", "/network_scan", "network_scan"),
    ("list_activity_events", "/app_events", "app_events"),
    (
        "list_notifications",
        "/notifications_history",
        "notifications_history",
    ),
];

fn health_fixture(name: &str) -> String {
    fixture(GROUP, name)
}

fn health_json(name: &str) -> Value {
    fixture_json(GROUP, name)
}

fn route(suffix: &str) -> String {
    format!("{NETWORK}{suffix}")
}

fn tool<'a>(tools: &'a [Tool], name: &str) -> &'a Tool {
    tools
        .iter()
        .find(|tool| tool.name == name)
        .unwrap_or_else(|| panic!("tool {name} is not listed"))
}

fn properties(tool: &Tool) -> BTreeMap<String, Value> {
    tool.input_schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|map| map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

/// Mounts `GET route` requiring both credentials but accepting any query, for the tests whose
/// query depends on the clock; the tests then read the query off the received request.
async fn mount_any_query(h: &Harness, route: &str, body: &str, calls: u64) {
    Mock::given(method("GET"))
        .and(path(route))
        .and(common::user_token_header())
        .and(common::session_cookie())
        .respond_with(json_response(body))
        .expect(calls)
        .mount(&h.mock)
        .await;
}

fn query_of(request: &Request) -> BTreeMap<String, String> {
    request
        .url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

/// The members of a success object, sorted.
fn members(out: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = out
        .as_object()
        .map(|object| object.keys().map(String::as_str).collect())
        .unwrap_or_default();
    keys.sort_unstable();
    keys
}

/// The text of an out-of-range `bad` value that an error message must not echo; the values that
/// are also digits of the fixed range text (0, 1, 100) are not checked.
fn echoed(bad: i64) -> String {
    if (-1..=100).contains(&bad) {
        String::new()
    } else {
        bad.to_string()
    }
}

/// Calls `tool` expecting rmcp's own argument-deserialisation failure.
async fn assert_rejected_by_rmcp(h: &Harness, tool: &str, args: JsonObject) -> anyhow::Result<()> {
    let result = h.call(tool, args.clone()).await?;
    assert_eq!(result.is_error, Some(true), "{tool} {args:?}");
    let text = result.content[0].as_text().expect("text").text.clone();
    assert!(
        text.starts_with("failed to deserialize parameters"),
        "{tool} {args:?}: {text}"
    );
    Ok(())
}

/// Calls `tool` expecting an `invalid_argument` about `field` that does not echo `input`.
async fn assert_invalid(
    h: &Harness,
    tool: &str,
    args: JsonObject,
    field: &str,
    input: &str,
) -> anyhow::Result<()> {
    let err = h.call_err(tool, args.clone()).await?;
    assert_eq!(err["error"]["code"], "invalid_argument", "{tool} {args:?}");
    assert_eq!(err["error"]["field"], field, "{tool} {args:?}");
    let message = err["error"]["message"].as_str().unwrap_or_default();
    assert!(!message.is_empty(), "{tool} {args:?}");
    assert!(
        input.is_empty() || !message.contains(input),
        "{tool} {args:?}: the message echoes the input: {message}"
    );
    Ok(())
}

// ===================== the listed tools =====================

#[tokio::test]
async fn the_seven_health_tools_are_listed_read_only_with_titles_and_output_schemas()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for (name, _, _) in HEALTH_TOOLS {
        let listed = tool(&tools, name);
        let annotations = listed
            .annotations
            .as_ref()
            .unwrap_or_else(|| panic!("{name} has annotations"));
        assert_eq!(annotations.read_only_hint, Some(true), "{name}");
        assert_eq!(annotations.destructive_hint, Some(false), "{name}");
        assert_eq!(annotations.idempotent_hint, Some(true), "{name}");
        assert_eq!(annotations.open_world_hint, Some(true), "{name}");
        let title = listed.title.as_deref().unwrap_or_default();
        assert!(!title.is_empty(), "{name} has a title");
        assert_eq!(annotations.title.as_deref(), Some(title), "{name}");
        let description = listed.description.as_deref().unwrap_or_default();
        assert!(description.len() > 80, "{name} has a real description");
        assert!(listed.output_schema.is_some(), "{name} has an outputSchema");
        assert_eq!(
            listed.input_schema.get("type"),
            Some(&json!("object")),
            "{name}"
        );
        assert_eq!(
            listed.input_schema.get("additionalProperties"),
            Some(&json!(false)),
            "{name} rejects unknown fields"
        );
        assert!(
            listed.input_schema.get("required").is_none(),
            "{name}: every input is optional"
        );
    }
    Ok(())
}

#[tokio::test]
async fn each_health_tool_publishes_exactly_its_documented_inputs_and_no_refresh()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    let expected: [(&str, &[&str]); 7] = [
        ("list_speed_tests", &["end", "limit", "network_id", "start"]),
        ("get_diagnostics", &["network_id"]),
        ("get_firmware_updates", &["network_id"]),
        (
            "get_channel_utilization",
            &[
                "band",
                "busy_threshold",
                "eero_id",
                "end",
                "granularity",
                "network_id",
                "start",
            ],
        ),
        ("get_network_scan", &["network_id"]),
        (
            "list_activity_events",
            &["before", "network_id", "page_size"],
        ),
        ("list_notifications", &["before", "network_id"]),
    ];
    for (name, inputs) in expected {
        let found: Vec<String> = properties(tool(&tools, name)).into_keys().collect();
        assert_eq!(found, inputs, "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn the_input_schemas_publish_ranges_enumerations_and_string_ids() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    let speed = properties(tool(&tools, "list_speed_tests"));
    assert_eq!(speed["limit"]["type"], "integer");
    assert_eq!(speed["limit"]["minimum"], 1);
    assert_eq!(speed["limit"]["maximum"], 100);
    assert_eq!(speed["start"]["type"], "string");
    assert_eq!(speed["end"]["type"], "string");

    let events = properties(tool(&tools, "list_activity_events"));
    assert_eq!(events["page_size"]["type"], "integer");
    assert_eq!(events["page_size"]["minimum"], 1);
    assert_eq!(events["page_size"]["maximum"], 100);
    assert_eq!(events["before"]["type"], "string");
    let notifications = properties(tool(&tools, "list_notifications"));
    assert_eq!(notifications["before"]["type"], "string");

    let channels = properties(tool(&tools, "get_channel_utilization"));
    for name in ["granularity", "busy_threshold"] {
        assert_eq!(channels[name]["type"], "integer", "{name}");
        assert_eq!(channels[name]["minimum"], 1, "{name}");
        assert!(channels[name].get("maximum").is_none(), "{name}");
    }
    let words = |name: &str| {
        channels[name]["description"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
    };
    assert!(words("granularity").starts_with("minutes per sample"));
    assert!(words("busy_threshold").starts_with("minimum busy threshold"));
    assert_eq!(channels["eero_id"]["type"], "string");
    assert_eq!(channels["band"]["type"], "string");
    assert_eq!(
        channels["band"]["enum"],
        json!([
            "band_2_4GHz",
            "band_5GHz_low",
            "band_5GHz_high",
            "band_5GHz_full",
            "band_6GHz"
        ])
    );
    for (name, _, _) in HEALTH_TOOLS {
        assert_eq!(
            properties(tool(&tools, name))["network_id"]["type"],
            "string",
            "{name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_descriptions_state_that_nothing_is_started_or_changed() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;
    let description = |name: &str| {
        tool(&tools, name)
            .description
            .as_deref()
            .unwrap_or_default()
            .to_owned()
    };

    assert!(description("get_diagnostics").contains("never starts a diagnostics run"));
    assert!(description("list_speed_tests").contains("never starts a speed test"));
    assert!(description("get_firmware_updates").contains("never applies an update"));
    assert!(description("list_notifications").contains("never marks anything as read"));
    assert!(description("get_channel_utilization").contains("24 hours"));
    assert!(description("get_channel_utilization").contains("granularity (minutes per sample)"));
    Ok(())
}

// ===================== list_speed_tests =====================

#[tokio::test]
async fn list_speed_tests_reads_speedtest_with_no_query_when_nothing_is_given() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.mount_get(&route("/speedtest"), &health_fixture("speed_tests"), 1)
        .await;

    let out = h
        .call_ok("list_speed_tests", object!({"network_id": "network-0001"}))
        .await?;

    let wire = health_json("speed_tests");
    assert_eq!(
        out["data"], wire["data"],
        "no deny-listed key in this fixture"
    );
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(members(&out), ["data", "network_id", "server_time"]);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/speedtest"],
        "no default window: no query at all"
    );
    Ok(())
}

#[tokio::test]
async fn list_speed_tests_sends_rusteeros_camel_case_names_and_passes_timestamps_through()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get_with(
        &route("/speedtest"),
        &[
            ("limit", "5"),
            ("startTime", "2026-10-16T00:00:00+02:00"),
            ("endTime", "2026-10-23T00:00:00.250z"),
        ],
        &health_fixture("speed_tests"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "list_speed_tests",
            object!({
                "network_id": "network-0001",
                "limit": 5,
                "start": "2026-10-16T00:00:00+02:00",
                "end": "2026-10-23T00:00:00.250z"
            }),
        )
        .await?;

    assert_eq!(out["network_id"], "network-0001");
    assert!(
        out.get("window").is_none(),
        "no window echo without a default window"
    );
    Ok(())
}

#[tokio::test]
async fn list_speed_tests_sends_only_the_inputs_that_were_given() -> anyhow::Result<()> {
    let cases: [(JsonObject, Vec<(&str, &str)>); 5] = [
        (object!({"limit": 1}), vec![("limit", "1")]),
        (object!({"limit": 100}), vec![("limit", "100")]),
        (
            object!({"start": "2026-10-16T00:00:00Z"}),
            vec![("startTime", "2026-10-16T00:00:00Z")],
        ),
        (
            object!({"end": "2026-10-23T00:00:00Z"}),
            vec![("endTime", "2026-10-23T00:00:00Z")],
        ),
        (
            object!({"limit": 20, "end": "2026-10-23T00:00:00Z"}),
            vec![("limit", "20"), ("endTime", "2026-10-23T00:00:00Z")],
        ),
    ];
    for (mut args, query) in cases {
        let h = Harness::start().await?;
        h.mount_get_with(
            &route("/speedtest"),
            &query,
            &health_fixture("speed_tests"),
            1,
        )
        .await;
        args.insert("network_id".to_owned(), json!("network-0001"));

        h.call_ok("list_speed_tests", args.clone()).await?;

        assert_eq!(h.received().await.len(), 1, "{args:?}");
    }
    Ok(())
}

#[tokio::test]
async fn list_speed_tests_rejects_a_limit_outside_1_to_100_before_any_request() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in [0_i64, -1, 101, 4_294_967_297, i64::MAX, i64::MIN] {
        let input = echoed(bad);
        assert_invalid(
            &h,
            "list_speed_tests",
            object!({"network_id": "network-0001", "limit": bad}),
            "limit",
            &input,
        )
        .await?;
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn list_speed_tests_rejects_malformed_timestamps_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in [
        "do-not-echo-me",
        "",
        "2026-10-17",
        "2026-10-17T00:00:00",
        "2026-10-17 00:00:00Z",
        "1760000000",
        "2026-13-16T00:00:00Z",
    ] {
        for field in ["start", "end"] {
            assert_invalid(
                &h,
                "list_speed_tests",
                object!({"network_id": "network-0001", field: bad}),
                field,
                bad,
            )
            .await?;
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn list_speed_tests_rejects_start_not_before_end_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    // Strictly before, comparing instants (the third pair is the same instant as 00:00Z).
    for (start, end) in [
        ("2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z"),
        ("2026-10-23T00:00:00Z", "2026-10-16T00:00:00Z"),
        ("2026-10-23T02:00:00+02:00", "2026-10-23T00:00:00Z"),
        ("2026-10-23T00:00:00Z", "2026-10-22T18:00:00-05:00"),
    ] {
        assert_invalid(
            &h,
            "list_speed_tests",
            object!({"network_id": "network-0001", "start": start, "end": end}),
            "start",
            "2026",
        )
        .await?;
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn list_speed_tests_compares_bounds_as_instants_and_forwards_them_unchanged()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get_with(
        &route("/speedtest"),
        &[
            ("startTime", "2026-10-23T00:00:00+02:00"),
            ("endTime", "2026-10-23T00:00:00Z"),
        ],
        &health_fixture("speed_tests"),
        1,
    )
    .await;

    // 00:00+02:00 is 22:00Z the day before: strictly before 00:00Z, although the local clock
    // readings are equal.
    h.call_ok(
        "list_speed_tests",
        object!({
            "network_id": "network-0001",
            "start": "2026-10-23T00:00:00+02:00",
            "end": "2026-10-23T00:00:00Z"
        }),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn list_speed_tests_rejects_wrong_types_unknown_fields_and_refresh() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for args in [
        object!({"limit": "5"}),
        object!({"limit": 5.5}),
        object!({"limit": true}),
        object!({"start": 1_760_000_000}),
        object!({"end": false}),
        object!({"bogus": 1}),
        object!({"refresh": true}),
        object!({"cadence": "daily"}),
    ] {
        assert_rejected_by_rmcp(&h, "list_speed_tests", args).await?;
    }
    h.assert_no_requests().await;
    Ok(())
}

// ===================== get_diagnostics =====================

#[tokio::test]
async fn get_diagnostics_reads_diagnostics_and_redacts_credentials() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(&route("/diagnostics"), &health_fixture("diagnostics"), 1)
        .await;

    let out = h
        .call_ok("get_diagnostics", object!({"network_id": "network-0001"}))
        .await?;

    let wire = health_json("diagnostics");
    let mut expected = wire["data"].clone();
    expected["wan"]["pppoe_credentials"] = json!(REDACTED);
    assert_eq!(out["data"], expected);
    assert_eq!(
        out["data"]["wan"]["pppoe_enabled"], true,
        "near-miss key untouched"
    );
    assert_eq!(out["data"]["results"], wire["data"]["results"]);
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(members(&out), ["data", "network_id", "server_time"]);
    let rendered = out.to_string();
    for secret in ["pppoepass000", "user@example.com"] {
        assert!(!rendered.contains(secret), "{secret} leaked");
    }
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/diagnostics"]
    );
    Ok(())
}

// ===================== get_firmware_updates =====================

#[tokio::test]
async fn get_firmware_updates_reads_updates() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(&route("/updates"), &health_fixture("updates"), 1)
        .await;

    let out = h
        .call_ok(
            "get_firmware_updates",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = health_json("updates");
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(
        out["data"]["scheduled_update_time"],
        Value::Null,
        "null stays visible"
    );
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/updates"]
    );
    Ok(())
}

// ===================== get_channel_utilization =====================

#[tokio::test]
async fn channel_utilization_defaults_to_the_last_24_hours_ending_now() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount_any_query(
        &h,
        &route("/channel_utilization"),
        &health_fixture("channel_utilization"),
        1,
    )
    .await;

    let before = Timestamp::now().as_second();
    let out = h
        .call_ok(
            "get_channel_utilization",
            object!({"network_id": "network-0001"}),
        )
        .await?;
    let after = Timestamp::now().as_second();

    let requests = h.received().await;
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].url.path(),
        "/2.2/networks/network-0001/channel_utilization"
    );
    let query = query_of(&requests[0]);
    assert_eq!(
        query.keys().map(String::as_str).collect::<Vec<_>>(),
        ["end", "start"],
        "a default window sends start and end and nothing else"
    );
    let start: Timestamp = query["start"].parse()?;
    let end: Timestamp = query["end"].parse()?;
    assert_eq!(
        end.as_second() - start.as_second(),
        24 * 3600,
        "24 hours apart"
    );
    assert!(
        (before..=after).contains(&end.as_second()),
        "the window ends now"
    );
    for bound in [&query["start"], &query["end"]] {
        assert!(
            bound.ends_with('Z') && !bound.contains('.'),
            "{bound}: UTC, whole seconds"
        );
    }

    assert_eq!(
        out["window"],
        json!({"start": query["start"], "end": query["end"]}),
        "the echo is the window that was sent, with no cadence or time zone"
    );
    let wire = health_json("channel_utilization");
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(
        members(&out),
        ["data", "network_id", "server_time", "window"]
    );
    Ok(())
}

#[tokio::test]
async fn channel_utilization_derives_the_missing_bound_24_hours_away() -> anyhow::Result<()> {
    let cases = [
        // (start, end given, start sent, end sent)
        (
            Some("2026-10-22T06:00:00Z"),
            None,
            "2026-10-22T06:00:00Z",
            "2026-10-23T06:00:00Z",
        ),
        (
            Some("2026-10-22T08:00:00+02:00"),
            None,
            "2026-10-22T08:00:00+02:00",
            "2026-10-23T06:00:00Z",
        ),
        (
            None,
            Some("2026-10-23T06:00:00Z"),
            "2026-10-22T06:00:00Z",
            "2026-10-23T06:00:00Z",
        ),
    ];
    for (start, end, start_sent, end_sent) in cases {
        let h = Harness::start().await?;
        h.mount_get_with(
            &route("/channel_utilization"),
            &[("start", start_sent), ("end", end_sent)],
            &health_fixture("channel_utilization"),
            1,
        )
        .await;
        let mut args = object!({"network_id": "network-0001"});
        if let Some(start) = start {
            args.insert("start".to_owned(), json!(start));
        }
        if let Some(end) = end {
            args.insert("end".to_owned(), json!(end));
        }

        let out = h.call_ok("get_channel_utilization", args.clone()).await?;

        assert_eq!(
            out["window"],
            json!({"start": start_sent, "end": end_sent}),
            "{args:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn channel_utilization_forwards_both_given_bounds_unchanged() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get_with(
        &route("/channel_utilization"),
        &[
            ("start", "2026-10-22T00:00:00+00:00"),
            ("end", "2026-10-23T12:30:00.5Z"),
        ],
        &health_fixture("channel_utilization"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_channel_utilization",
            object!({
                "network_id": "network-0001",
                "start": "2026-10-22T00:00:00+00:00",
                "end": "2026-10-23T12:30:00.5Z"
            }),
        )
        .await?;

    assert_eq!(
        out["window"],
        json!({"start": "2026-10-22T00:00:00+00:00", "end": "2026-10-23T12:30:00.5Z"})
    );
    Ok(())
}

#[tokio::test]
async fn channel_utilization_sends_every_filter_under_rusteeros_names() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get_with(
        &route("/channel_utilization"),
        &[
            ("start", "2026-10-22T00:00:00Z"),
            ("end", "2026-10-23T00:00:00Z"),
            ("eero_id", "eero-0001"),
            ("band", "band_5GHz_low"),
            ("granularity", "5"),
            ("busy_threshold", "40"),
        ],
        &health_fixture("channel_utilization"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_channel_utilization",
            object!({
                "network_id": "network-0001",
                "start": "2026-10-22T00:00:00Z",
                "end": "2026-10-23T00:00:00Z",
                "eero_id": "/2.2/eeros/eero-0001",
                "band": "band_5GHz_low",
                "granularity": 5,
                "busy_threshold": 40
            }),
        )
        .await?;

    assert_eq!(
        out["window"],
        json!({"start": "2026-10-22T00:00:00Z", "end": "2026-10-23T00:00:00Z"}),
        "the filters are not part of the window echo"
    );
    Ok(())
}

#[tokio::test]
async fn channel_utilization_sends_only_the_filters_that_were_given() -> anyhow::Result<()> {
    let window = [
        ("start", "2026-10-22T00:00:00Z"),
        ("end", "2026-10-23T00:00:00Z"),
    ];
    let cases: [(JsonObject, Vec<(&str, &str)>); 4] = [
        (
            object!({"eero_id": "eero-0002"}),
            vec![("eero_id", "eero-0002")],
        ),
        (object!({"band": "band_6GHz"}), vec![("band", "band_6GHz")]),
        (object!({"granularity": 1}), vec![("granularity", "1")]),
        (
            object!({"busy_threshold": 4_294_967_295_u32}),
            vec![("busy_threshold", "4294967295")],
        ),
    ];
    for (mut args, filter) in cases {
        let h = Harness::start().await?;
        let mut query = window.to_vec();
        query.extend(filter);
        h.mount_get_with(
            &route("/channel_utilization"),
            &query,
            &health_fixture("channel_utilization"),
            1,
        )
        .await;
        args.insert("network_id".to_owned(), json!("network-0001"));
        args.insert("start".to_owned(), json!(window[0].1));
        args.insert("end".to_owned(), json!(window[1].1));

        h.call_ok("get_channel_utilization", args.clone()).await?;

        assert_eq!(h.received().await.len(), 1, "{args:?}");
    }
    Ok(())
}

#[tokio::test]
async fn channel_utilization_sends_every_band_value_as_rusteero_spells_it() -> anyhow::Result<()> {
    for band in Band::ALL {
        let h = Harness::start().await?;
        h.mount_get_with(
            &route("/channel_utilization"),
            &[
                ("start", "2026-10-22T00:00:00Z"),
                ("end", "2026-10-23T00:00:00Z"),
                ("band", band.as_str()),
            ],
            &health_fixture("channel_utilization"),
            1,
        )
        .await;

        h.call_ok(
            "get_channel_utilization",
            object!({
                "network_id": "network-0001",
                "start": "2026-10-22T00:00:00Z",
                "end": "2026-10-23T00:00:00Z",
                "band": band.as_str()
            }),
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn channel_utilization_accepts_an_integer_eero_id_in_decimal() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get_with(
        &route("/channel_utilization"),
        &[
            ("start", "2026-10-22T00:00:00Z"),
            ("end", "2026-10-23T00:00:00Z"),
            ("eero_id", "12345"),
        ],
        &health_fixture("channel_utilization"),
        1,
    )
    .await;

    h.call_ok(
        "get_channel_utilization",
        object!({
            "network_id": "network-0001",
            "start": "2026-10-22T00:00:00Z",
            "end": "2026-10-23T00:00:00Z",
            "eero_id": 12345
        }),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn channel_utilization_rejects_a_bad_window_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in [
        "do-not-echo-me",
        "",
        "2026-10-17",
        "2026-10-17T00:00:00",
        "2026-13-16T00:00:00Z",
    ] {
        for field in ["start", "end"] {
            assert_invalid(
                &h,
                "get_channel_utilization",
                object!({"network_id": "network-0001", field: bad}),
                field,
                bad,
            )
            .await?;
        }
    }
    // Start must be strictly before end, comparing instants.
    for (start, end) in [
        ("2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z"),
        ("2026-10-24T00:00:00Z", "2026-10-23T00:00:00Z"),
        ("2026-10-23T02:00:00+02:00", "2026-10-23T00:00:00Z"),
    ] {
        assert_invalid(
            &h,
            "get_channel_utilization",
            object!({"network_id": "network-0001", "start": start, "end": end}),
            "start",
            "",
        )
        .await?;
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn channel_utilization_rejects_non_positive_integers_before_any_request() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for field in ["granularity", "busy_threshold"] {
        for bad in [0_i64, -1, -500, 4_294_967_296, i64::MAX, i64::MIN] {
            let input = echoed(bad);
            assert_invalid(
                &h,
                "get_channel_utilization",
                object!({"network_id": "network-0001", field: bad}),
                field,
                &input,
            )
            .await?;
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn channel_utilization_rejects_a_bad_eero_id_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in [
        "",
        "   ",
        "../hostile-0001",
        "a/b",
        "bad id",
        "-leading",
        "/2.2/networks/network-0001",
        "/2.2/eeros/eero-0001/connections",
        "https://api-user.e2ro.com/2.2/eeros/eero-0001",
        "http://other.test:1234/2.2/eeros/eero-0001",
    ] {
        let err = h
            .call_err(
                "get_channel_utilization",
                object!({"network_id": "network-0001", "eero_id": bad}),
            )
            .await?;
        assert_eq!(err["error"]["code"], "invalid_argument", "{bad:?}");
        assert_eq!(err["error"]["field"], "eero_id", "{bad:?}");
        let message = err["error"]["message"].as_str().unwrap_or_default();
        for echoed in ["hostile", "other.test", "e2ro", "connections", "bad id"] {
            assert!(!message.contains(echoed), "{bad:?}: {message}");
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn channel_utilization_rejects_wrong_types_and_unknown_values() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for args in [
        object!({"band": "band_5GHz"}),
        object!({"band": "BAND_6GHZ"}),
        object!({"band": ""}),
        object!({"band": 5}),
        object!({"granularity": "5"}),
        object!({"granularity": 2.5}),
        object!({"busy_threshold": true}),
        object!({"start": 1_760_000_000}),
        object!({"eero_id": 1.5}),
        object!({"eero_id": true}),
        object!({"gap_data_placeholder": -1}),
        object!({"refresh": true}),
        object!({"timezone": "UTC"}),
    ] {
        assert_rejected_by_rmcp(&h, "get_channel_utilization", args).await?;
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn channel_utilization_uses_the_only_network_and_the_default_window() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    mount_any_query(
        &h,
        &route("/channel_utilization"),
        &health_fixture("channel_utilization"),
        1,
    )
    .await;

    let out = h.call_ok("get_channel_utilization", object!({})).await?;

    assert_eq!(out["network_id"], "network-0001");
    let targets = h.targets().await;
    assert_eq!(targets[0], "GET /2.2/networks");
    assert!(
        targets[1].starts_with("GET /2.2/networks/network-0001/channel_utilization?"),
        "{targets:?}"
    );
    assert!(out["window"]["start"].is_string() && out["window"]["end"].is_string());
    Ok(())
}

// ===================== get_network_scan =====================

#[tokio::test]
async fn get_network_scan_reads_network_scan() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(&route("/network_scan"), &health_fixture("network_scan"), 1)
        .await;

    let out = h
        .call_ok("get_network_scan", object!({"network_id": "network-0001"}))
        .await?;

    let wire = health_json("network_scan");
    assert_eq!(
        out["data"], wire["data"],
        "SSIDs and BSSIDs are not secrets"
    );
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(members(&out), ["data", "network_id", "server_time"]);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/network_scan"]
    );
    Ok(())
}

// ===================== list_activity_events =====================

#[tokio::test]
async fn list_activity_events_reads_app_events_with_no_query_by_default() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(&route("/app_events"), &health_fixture("app_events"), 1)
        .await;

    let out = h
        .call_ok(
            "list_activity_events",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = health_json("app_events");
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["data"]["events"][0]["timestamp_ms"], "1790000100000");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(members(&out), ["data", "network_id", "server_time"]);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/app_events"]
    );
    Ok(())
}

#[tokio::test]
async fn list_activity_events_sends_page_size_and_before_as_timestamp() -> anyhow::Result<()> {
    let cases: [(JsonObject, Vec<(&str, &str)>); 4] = [
        (
            object!({"page_size": 25, "before": "2026-10-22T20:15:00-07:00"}),
            vec![
                ("page_size", "25"),
                ("timestamp", "2026-10-22T20:15:00-07:00"),
            ],
        ),
        (object!({"page_size": 1}), vec![("page_size", "1")]),
        (object!({"page_size": 100}), vec![("page_size", "100")]),
        (
            object!({"before": "2026-10-22T20:15:00.123Z"}),
            vec![("timestamp", "2026-10-22T20:15:00.123Z")],
        ),
    ];
    for (mut args, query) in cases {
        let h = Harness::start().await?;
        h.mount_get_with(
            &route("/app_events"),
            &query,
            &health_fixture("app_events"),
            1,
        )
        .await;
        args.insert("network_id".to_owned(), json!("network-0001"));

        h.call_ok("list_activity_events", args.clone()).await?;

        assert_eq!(h.received().await.len(), 1, "{args:?}");
    }
    Ok(())
}

#[tokio::test]
async fn list_activity_events_rejects_a_bad_page_size_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in [0_i64, -1, 101, 4_294_967_297, i64::MAX, i64::MIN] {
        let input = echoed(bad);
        assert_invalid(
            &h,
            "list_activity_events",
            object!({"network_id": "network-0001", "page_size": bad}),
            "page_size",
            &input,
        )
        .await?;
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn the_before_cursor_must_be_an_rfc_3339_timestamp_on_both_tools() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for tool in ["list_activity_events", "list_notifications"] {
        for bad in [
            "do-not-echo-me",
            "",
            "yesterday",
            "2026-10-17",
            "2026-10-17T00:00:00",
            "2026-10-17T00:00:00+0000",
            "1760000000",
            "2026-10-17T25:00:00Z",
        ] {
            assert_invalid(
                &h,
                tool,
                object!({"network_id": "network-0001", "before": bad}),
                "before",
                bad,
            )
            .await?;
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn list_activity_events_rejects_wrong_types_unknown_fields_and_refresh() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for args in [
        object!({"page_size": "25"}),
        object!({"page_size": 2.5}),
        object!({"before": 1_760_000_000}),
        object!({"limit": 10}),
        object!({"timestamp": "2026-10-16T00:00:00Z"}),
        object!({"refresh": false}),
    ] {
        assert_rejected_by_rmcp(&h, "list_activity_events", args).await?;
    }
    h.assert_no_requests().await;
    Ok(())
}

// ===================== list_notifications =====================

#[tokio::test]
async fn list_notifications_reads_notifications_history_with_no_query_by_default()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        &route("/notifications_history"),
        &health_fixture("notifications_history"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "list_notifications",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = health_json("notifications_history");
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(members(&out), ["data", "network_id", "server_time"]);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/notifications_history"]
    );
    Ok(())
}

#[tokio::test]
async fn list_notifications_sends_before_as_the_timestamp_parameter() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get_with(
        &route("/notifications_history"),
        &[("timestamp", "2026-10-22T20:15:00+02:00")],
        &health_fixture("notifications_history"),
        1,
    )
    .await;

    h.call_ok(
        "list_notifications",
        object!({"network_id": "network-0001", "before": "2026-10-22T20:15:00+02:00"}),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn list_notifications_rejects_wrong_types_unknown_fields_and_refresh() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for args in [
        object!({"before": 5}),
        object!({"before": ["2026-10-16T00:00:00Z"]}),
        object!({"page_size": 10}),
        object!({"mark_read": true}),
        object!({"refresh": true}),
    ] {
        assert_rejected_by_rmcp(&h, "list_notifications", args).await?;
    }
    h.assert_no_requests().await;
    Ok(())
}

// ===================== network resolution, on every health tool =====================

// ===================== validation runs before default-network resolution =====================
//
// With network_id omitted, a valid call first reads the account's networks. An invalid argument
// must fail before that: nothing is mounted and no request may reach the wire. (Every other
// validation test passes an explicit network_id, which resolves without any request, so those
// cannot tell the two orders apart.)

#[tokio::test]
async fn list_speed_tests_validates_before_resolving_the_default_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    assert_invalid(&h, "list_speed_tests", object!({"limit": 0}), "limit", "").await?;
    assert_invalid(
        &h,
        "list_speed_tests",
        object!({"start": "do-not-echo-me"}),
        "start",
        "do-not-echo-me",
    )
    .await?;
    assert_invalid(
        &h,
        "list_speed_tests",
        object!({"end": "do-not-echo-me"}),
        "end",
        "do-not-echo-me",
    )
    .await?;
    assert_invalid(
        &h,
        "list_speed_tests",
        object!({"start": "2026-10-23T00:00:00Z", "end": "2026-10-16T00:00:00Z"}),
        "start",
        "2026",
    )
    .await?;
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn get_channel_utilization_validates_before_resolving_the_default_network()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    assert_invalid(
        &h,
        "get_channel_utilization",
        object!({"start": "do-not-echo-me"}),
        "start",
        "do-not-echo-me",
    )
    .await?;
    assert_invalid(
        &h,
        "get_channel_utilization",
        object!({"start": "2026-10-23T00:00:00Z", "end": "2026-10-16T00:00:00Z"}),
        "start",
        "2026",
    )
    .await?;
    assert_invalid(
        &h,
        "get_channel_utilization",
        object!({"eero_id": "a/b"}),
        "eero_id",
        "a/b",
    )
    .await?;
    assert_invalid(
        &h,
        "get_channel_utilization",
        object!({"granularity": 0}),
        "granularity",
        "",
    )
    .await?;
    assert_invalid(
        &h,
        "get_channel_utilization",
        object!({"busy_threshold": 0}),
        "busy_threshold",
        "",
    )
    .await?;
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn list_activity_events_validates_before_resolving_the_default_network() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    assert_invalid(
        &h,
        "list_activity_events",
        object!({"page_size": 0}),
        "page_size",
        "",
    )
    .await?;
    assert_invalid(
        &h,
        "list_activity_events",
        object!({"before": "do-not-echo-me"}),
        "before",
        "do-not-echo-me",
    )
    .await?;
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn list_notifications_validates_before_resolving_the_default_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    assert_invalid(
        &h,
        "list_notifications",
        object!({"before": "do-not-echo-me"}),
        "before",
        "do-not-echo-me",
    )
    .await?;
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn an_omitted_network_id_uses_the_only_network_on_every_health_tool() -> anyhow::Result<()> {
    for (name, suffix, fixture_name) in HEALTH_TOOLS {
        let h = Harness::start().await?;
        h.mount_single_network(1).await;
        mount_any_query(&h, &route(suffix), &health_fixture(fixture_name), 1).await;

        let out = h.call_ok(name, object!({})).await?;

        assert_eq!(out["network_id"], "network-0001", "{name}");
        let targets = h.targets().await;
        assert_eq!(targets.len(), 2, "{name}: {targets:?}");
        assert_eq!(targets[0], "GET /2.2/networks", "{name}");
        assert!(
            targets[1].starts_with(&format!("GET {}", route(suffix))),
            "{name}: {targets:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn several_networks_without_a_network_id_list_each_id_and_read_nothing_else()
-> anyhow::Result<()> {
    let networks = json!({
        "meta": {"code": 200, "server_time": "2026-10-23T12:00:00Z"},
        "data": [
            {"url": "/2.2/networks/network-0001", "name": "Example-Network"},
            {"url": "/2.2/networks/network-0002", "name": "Second-Network"}
        ]
    })
    .to_string();
    for (name, _, _) in HEALTH_TOOLS {
        let h = Harness::start().await?;
        h.mount_get("/2.2/networks", &networks, 1).await;

        let err = h.call_err(name, object!({})).await?;

        assert_eq!(err["error"]["code"], "invalid_argument", "{name}");
        assert_eq!(err["error"]["field"], "network_id", "{name}");
        let message = err["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("network-0001 (Example-Network)"),
            "{name}: {message}"
        );
        assert!(
            message.contains("network-0002 (Second-Network)"),
            "{name}: {message}"
        );
        assert_eq!(h.targets().await, ["GET /2.2/networks"], "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn an_explicit_network_id_in_any_form_reaches_the_same_read() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    let forms = [
        json!("network-0001"),
        json!("/2.2/networks/network-0001"),
        json!(format!("{origin}/2.2/networks/network-0001/")),
        json!(" network-0001 "),
    ];
    h.mount_get(
        &route("/updates"),
        &health_fixture("updates"),
        u64::try_from(forms.len())?,
    )
    .await;

    for form in forms {
        let out = h
            .call_ok(
                "get_firmware_updates",
                object!({"network_id": form.clone()}),
            )
            .await?;
        assert_eq!(out["network_id"], "network-0001", "{form}");
    }
    let integer = h
        .call_err("get_firmware_updates", object!({"network_id": 12345}))
        .await;
    // An integer id is accepted; nothing is mounted for it, so the mock answers 404.
    assert_eq!(integer?["error"]["code"], "not_found");
    assert!(
        h.targets()
            .await
            .iter()
            .any(|target| target == "GET /2.2/networks/12345/updates"),
        "an integer id is rendered in decimal"
    );
    Ok(())
}

#[tokio::test]
async fn invalid_network_ids_fail_before_any_request_on_every_health_tool() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    let bad_ids = [
        "",
        "   ",
        "../hostile-0001",
        "a/b",
        "bad id",
        "-leading",
        "/2.2/eeros/eero-0001",
        "/2.2/networks/network-0001/devices",
        "https://api-user.e2ro.com/2.2/networks/network-0001",
        "http://other.test:1234/2.2/networks/network-0001",
    ];
    for (name, _, _) in HEALTH_TOOLS {
        for bad in bad_ids {
            let err = h.call_err(name, object!({"network_id": bad})).await?;
            assert_eq!(err["error"]["code"], "invalid_argument", "{name} {bad:?}");
            assert_eq!(err["error"]["field"], "network_id", "{name} {bad:?}");
            let message = err["error"]["message"].as_str().unwrap_or_default();
            for echoed in ["hostile", "other.test", "e2ro", "eero-0001", "devices"] {
                assert!(!message.contains(echoed), "{name} {bad:?}: {message}");
            }
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn no_health_tool_offers_refresh_or_accepts_unknown_fields() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for (name, _, _) in HEALTH_TOOLS {
        for args in [object!({"refresh": true}), object!({"bogus": 1})] {
            assert_rejected_by_rmcp(&h, name, args).await?;
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn every_health_tool_works_with_the_arguments_member_omitted() -> anyhow::Result<()> {
    for (name, suffix, fixture_name) in HEALTH_TOOLS {
        let h = Harness::start().await?;
        h.mount_single_network(1).await;
        mount_any_query(&h, &route(suffix), &health_fixture(fixture_name), 1).await;

        let result = h.call_without_arguments(name).await?;

        let out = common::structured(&result)?;
        assert_eq!(out["network_id"], "network-0001", "{name}");
    }
    Ok(())
}

// ===================== upstream failures =====================

#[tokio::test]
async fn upstream_failures_are_mapped_on_every_health_tool() -> anyhow::Result<()> {
    for (name, suffix, _) in HEALTH_TOOLS {
        for (status, upstream_code, expected) in [
            (404_u16, None, "not_found"),
            (403, Some("error.access.denied"), "access_denied"),
            (
                401,
                Some("error.session.expired"),
                "authentication_required",
            ),
        ] {
            let h = Harness::start().await?;
            let template = match upstream_code {
                Some(code) => json_status(
                    status,
                    &json!({"meta": {"code": status, "error": code}, "data": {}}),
                ),
                None => ResponseTemplate::new(status),
            };
            Mock::given(method("GET"))
                .and(path(route(suffix)))
                .respond_with(template)
                .expect(1)
                .mount(&h.mock)
                .await;

            let err = h
                .call_err(name, object!({"network_id": "network-0001"}))
                .await?;

            assert_eq!(err["error"]["code"], expected, "{name} {status}");
            assert_eq!(err["error"]["upstream_status"], status, "{name} {status}");
            let rendered = err.to_string();
            for leak in ["network-0001", "127.0.0.1", "/2.2/"] {
                assert!(!rendered.contains(leak), "{name} {status}: {leak} leaked");
            }
        }
    }
    Ok(())
}
