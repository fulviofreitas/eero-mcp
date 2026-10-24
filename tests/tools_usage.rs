//! Pins the usage-group tools (33 to 40): the listing, annotations and input schemas, the exact
//! GET path and query (names and values, nothing extra), both credentials, the output shape
//! (`data`, `network_id`, `server_time`, `window`), the 7-day default window, one-bound
//! derivation, window and id validation before any request, default-network resolution, the
//! absence of any cache, redaction, and the premium and not-supported error cases.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use common::{
    Harness, TEST_TOKEN, authed_get_with, fixture, fixture_json, json_response, json_status,
    session_cookie, user_token_header,
};
use jiff::Timestamp;
use rmcp::model::{JsonObject, Tool};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, Request};

const GROUP: &str = "usage";
const REDACTED: &str = "[REDACTED]";
const NET: &str = "network-0001";
const MAC: &str = "aa:bb:cc:00:00:01";
const START: &str = "2026-10-16T00:00:00Z";
const END: &str = "2026-10-23T00:00:00Z";
const WEEK_SECONDS: i64 = 7 * 24 * 60 * 60;

fn usage_fixture(name: &str) -> String {
    fixture(GROUP, name)
}

fn usage_json(name: &str) -> Value {
    fixture_json(GROUP, name)
}

fn object(value: Value) -> JsonObject {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

/// One tool of the group: its route in `network-0001`, its fixture, and the child id it needs.
struct Spec {
    name: &'static str,
    route: &'static str,
    fixture: &'static str,
    /// Required arguments (a device MAC, a profile id or a device id), as name and value.
    required: &'static [(&'static str, &'static str)],
    /// Insights tools take `insight_type`; usage tools take `timezone`.
    insights: bool,
}

const GET_DATA_USAGE: Spec = Spec {
    name: "get_data_usage",
    route: "/2.2/networks/network-0001/data_usage",
    fixture: "data_usage",
    required: &[],
    insights: false,
};
const GET_DEVICES_DATA_USAGE: Spec = Spec {
    name: "get_devices_data_usage",
    route: "/2.2/networks/network-0001/data_usage/devices",
    fixture: "devices_data_usage",
    required: &[],
    insights: false,
};
const GET_DEVICE_DATA_USAGE: Spec = Spec {
    name: "get_device_data_usage",
    route: "/2.2/networks/network-0001/data_usage/devices/aa:bb:cc:00:00:01",
    fixture: "device_data_usage",
    required: &[("device_mac", MAC)],
    insights: false,
};
const GET_EEROS_DATA_USAGE: Spec = Spec {
    name: "get_eeros_data_usage",
    route: "/2.2/networks/network-0001/data_usage/eeros",
    fixture: "eeros_data_usage",
    required: &[],
    insights: false,
};
const GET_PROFILE_DATA_USAGE: Spec = Spec {
    name: "get_profile_data_usage",
    route: "/2.2/networks/network-0001/data_usage/profiles/profile-0001",
    fixture: "profile_data_usage",
    required: &[("profile_id", "profile-0001")],
    insights: false,
};
const GET_INSIGHTS: Spec = Spec {
    name: "get_insights",
    route: "/2.2/networks/network-0001/insights",
    fixture: "insights",
    required: &[],
    insights: true,
};
const GET_DEVICES_INSIGHTS: Spec = Spec {
    name: "get_devices_insights",
    route: "/2.2/networks/network-0001/insights/devices",
    fixture: "devices_insights",
    required: &[],
    insights: true,
};
const GET_DEVICE_INSIGHTS: Spec = Spec {
    name: "get_device_insights",
    route: "/2.2/networks/network-0001/insights/devices/aa:bb:cc:00:00:01",
    fixture: "device_insights",
    required: &[("device_id", MAC)],
    insights: true,
};

const ALL: [&Spec; 8] = [
    &GET_DATA_USAGE,
    &GET_DEVICES_DATA_USAGE,
    &GET_DEVICE_DATA_USAGE,
    &GET_EEROS_DATA_USAGE,
    &GET_PROFILE_DATA_USAGE,
    &GET_INSIGHTS,
    &GET_DEVICES_INSIGHTS,
    &GET_DEVICE_INSIGHTS,
];
const INSIGHT_TOOLS: [&Spec; 3] = [&GET_INSIGHTS, &GET_DEVICES_INSIGHTS, &GET_DEVICE_INSIGHTS];
/// The five tools that take `timezone` (tools 33 to 37).
const DATA_USAGE_TOOLS: [&Spec; 5] = [
    &GET_DATA_USAGE,
    &GET_DEVICES_DATA_USAGE,
    &GET_DEVICE_DATA_USAGE,
    &GET_EEROS_DATA_USAGE,
    &GET_PROFILE_DATA_USAGE,
];

/// The arguments a call needs besides the network: the required child id.
fn required_args(spec: &Spec) -> JsonObject {
    spec.required
        .iter()
        .map(|(name, value)| ((*name).to_owned(), json!(value)))
        .collect()
}

/// The required child id, `network_id` set to `network-0001`, and `extra` merged on top.
fn args(spec: &Spec, extra: Value) -> JsonObject {
    let mut map = required_args(spec);
    map.insert("network_id".to_owned(), json!(NET));
    map.extend(object(extra));
    map
}

/// The required child id and `extra`, with no `network_id` (default-network resolution).
fn args_without_network(spec: &Spec, extra: Value) -> JsonObject {
    let mut map = required_args(spec);
    map.extend(object(extra));
    map
}

/// The exact query a call with the fixed window and `cadence` must send: `start`, `end`,
/// `cadence`, then `rest`. The insights tools add their `insight_type` in `rest`.
fn query<'a>(cadence: &'a str, rest: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    let mut pairs = vec![("start", START), ("end", END), ("cadence", cadence)];
    pairs.extend_from_slice(rest);
    pairs
}

/// The default query of a tool for the fixed window: daily, and `blocked` for insights.
fn default_query(spec: &Spec) -> Vec<(&'static str, &'static str)> {
    if spec.insights {
        query("daily", &[("insight_type", "blocked")])
    } else {
        query("daily", &[])
    }
}

/// The exact query for an arbitrary window: `start`, `end`, `cadence`, and the default
/// `insight_type` on the insights tools.
fn window_query<'a>(
    spec: &Spec,
    start: &'a str,
    end: &'a str,
    cadence: &'a str,
) -> Vec<(&'a str, &'a str)> {
    let mut pairs = vec![("start", start), ("end", end), ("cadence", cadence)];
    if spec.insights {
        pairs.push(("insight_type", "blocked"));
    }
    pairs
}

/// The fixed window as call arguments.
fn window_args() -> Value {
    json!({"start": START, "end": END})
}

async fn mount(h: &Harness, spec: &Spec, query: &[(&str, &str)], calls: u64) {
    h.mount_get_with(spec.route, query, &usage_fixture(spec.fixture), calls)
        .await;
}

fn query_of(request: &Request) -> BTreeMap<String, String> {
    request
        .url
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn tool<'a>(tools: &'a [Tool], name: &str) -> &'a Tool {
    tools
        .iter()
        .find(|tool| tool.name == name)
        .unwrap_or_else(|| panic!("tool {name} is not listed"))
}

fn property_names(tool: &Tool) -> BTreeSet<String> {
    tool.input_schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| properties.keys().cloned().collect())
        .unwrap_or_default()
}

fn required_names(tool: &Tool) -> BTreeSet<String> {
    tool.input_schema
        .get("required")
        .and_then(Value::as_array)
        .map(|names| {
            names
                .iter()
                .filter_map(|name| name.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The properties a tool publishes: the shared window inputs, then its own.
fn expected_properties(spec: &Spec) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = ["network_id", "start", "end", "cadence"]
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    names.insert(if spec.insights {
        "insight_type".to_owned()
    } else {
        "timezone".to_owned()
    });
    names.extend(spec.required.iter().map(|(name, _)| (*name).to_owned()));
    if spec.name == "get_devices_data_usage" {
        names.insert("profile_id".to_owned());
    }
    names
}

// ===================== the listed tools =====================

#[tokio::test]
async fn the_eight_usage_tools_are_listed_read_only_with_titles_and_output_schemas()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for spec in ALL {
        let name = spec.name;
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
        assert!(description.len() > 200, "{name} has a real description");
        assert!(
            description.contains("last 7 days"),
            "{name} states the default window"
        );
        assert!(listed.output_schema.is_some(), "{name} has an outputSchema");
        assert_eq!(
            listed.input_schema.get("additionalProperties"),
            Some(&json!(false)),
            "{name} rejects unknown fields"
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_input_schemas_publish_exactly_the_documented_properties() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for spec in ALL {
        let listed = tool(&tools, spec.name);
        assert_eq!(
            property_names(listed),
            expected_properties(spec),
            "{}",
            spec.name
        );
        let required: BTreeSet<String> = spec
            .required
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        assert_eq!(required_names(listed), required, "{}", spec.name);

        let properties = &listed.input_schema["properties"];
        assert_eq!(properties["cadence"]["enum"], json!(["daily", "hourly"]));
        for id in ["network_id", "device_mac", "device_id", "profile_id"] {
            if let Some(definition) = properties.get(id) {
                assert_eq!(definition["type"], "string", "{}.{id}", spec.name);
            }
        }
        for window_bound in ["start", "end", "timezone"] {
            if let Some(definition) = properties.get(window_bound) {
                assert_eq!(definition["type"], "string", "{}.{window_bound}", spec.name);
            }
        }
        if spec.insights {
            assert_eq!(
                properties["insight_type"]["enum"],
                json!([
                    "inspected",
                    "blocked",
                    "malware",
                    "phishing",
                    "botnet",
                    "filtered",
                    "adult",
                    "illegal",
                    "violent",
                    "adblock",
                    "datausage"
                ]),
                "{}",
                spec.name
            );
        }
        // None of the eight is backed by a cached getter.
        assert!(
            !property_names(listed).contains("refresh"),
            "{} has no refresh",
            spec.name
        );
    }
    Ok(())
}

// ===================== happy paths: path, query, credentials, output =====================

#[tokio::test]
async fn every_usage_tool_sends_one_exact_get_and_shapes_the_output() -> anyhow::Result<()> {
    for spec in ALL {
        let h = Harness::start().await?;
        // authed_get_with requires both credential headers and pins the query exactly.
        mount(&h, spec, &default_query(spec), 1).await;

        let out = h.call_ok(spec.name, args(spec, window_args())).await?;

        let wire = usage_json(spec.fixture);
        let name = spec.name;
        assert_eq!(out["data"], wire["data"], "{name}: no deny-listed key");
        assert_eq!(out["network_id"], NET, "{name}");
        assert_eq!(out["server_time"], wire["meta"]["server_time"], "{name}");
        let expected_window = if spec.insights {
            json!({"start": START, "end": END, "cadence": "daily", "insight_type": "blocked"})
        } else {
            json!({"start": START, "end": END, "cadence": "daily"})
        };
        assert_eq!(out["window"], expected_window, "{name}");
        assert_eq!(
            out.as_object()
                .map(|o| o.keys().cloned().collect::<Vec<_>>()),
            Some(vec![
                "data".to_owned(),
                "network_id".to_owned(),
                "server_time".to_owned(),
                "window".to_owned()
            ]),
            "{name}: only the documented members"
        );
        assert!(
            out.get("detail").is_none() && out.get("count").is_none(),
            "{name}"
        );

        let targets = h.targets().await;
        assert_eq!(targets.len(), 1, "{name}");
        assert!(
            targets[0].starts_with(&format!("GET {}?", spec.route)),
            "{name}: {}",
            targets[0]
        );
        for request in h.received().await {
            assert_eq!(request.method.as_str(), "GET", "{name}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn the_device_mac_travels_as_one_path_segment() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(
        &h,
        &GET_DEVICE_DATA_USAGE,
        &default_query(&GET_DEVICE_DATA_USAGE),
        1,
    )
    .await;

    h.call_ok(
        "get_device_data_usage",
        args(&GET_DEVICE_DATA_USAGE, window_args()),
    )
    .await?;

    let requests = h.received().await;
    assert_eq!(
        requests[0].url.path(),
        "/2.2/networks/network-0001/data_usage/devices/aa:bb:cc:00:00:01"
    );
    Ok(())
}

// ===================== get_data_usage =====================

#[tokio::test]
async fn every_data_usage_tool_passes_cadence_and_timezone_through_and_echoes_them()
-> anyhow::Result<()> {
    // The exact-query mount pins the values on the wire: the echo is built from the same struct
    // as the request arguments, so asserting on it alone would not show they reached eero.
    for spec in DATA_USAGE_TOOLS {
        let h = Harness::start().await?;
        mount(
            &h,
            spec,
            &query("hourly", &[("timezone", "America/Los_Angeles")]),
            1,
        )
        .await;

        let out = h
            .call_ok(
                spec.name,
                args(
                    spec,
                    json!({
                        "start": START,
                        "end": END,
                        "cadence": "hourly",
                        "timezone": "America/Los_Angeles"
                    }),
                ),
            )
            .await?;

        assert_eq!(
            out["window"],
            json!({
                "start": START,
                "end": END,
                "cadence": "hourly",
                "timezone": "America/Los_Angeles"
            }),
            "{}",
            spec.name
        );
        let sent = query_of(&h.received().await[0]);
        assert_eq!(sent["cadence"], "hourly", "{}", spec.name);
        assert_eq!(sent["timezone"], "America/Los_Angeles", "{}", spec.name);
    }
    Ok(())
}

#[tokio::test]
async fn the_timezone_is_sent_exactly_as_given_and_never_added() -> anyhow::Result<()> {
    // An unknown zone is eero's to judge: it is forwarded unchanged. Without one, no timezone
    // parameter is sent at all (the exact-query mock rejects any extra parameter).
    for zone in ["Not/AZone", "utc", "Europe/Berlin"] {
        for spec in DATA_USAGE_TOOLS {
            let h = Harness::start().await?;
            mount(&h, spec, &query("daily", &[("timezone", zone)]), 1).await;
            let out = h
                .call_ok(
                    spec.name,
                    args(spec, json!({"start": START, "end": END, "timezone": zone})),
                )
                .await?;
            assert_eq!(out["window"]["timezone"], zone, "{}", spec.name);
        }
    }
    Ok(())
}

// ===================== get_devices_data_usage =====================

#[tokio::test]
async fn get_devices_data_usage_always_sends_a_cadence_defaulting_to_daily() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // The read's cadence is optional in rusteero; the tool never leaves it out.
    mount(&h, &GET_DEVICES_DATA_USAGE, &query("daily", &[]), 1).await;

    let out = h
        .call_ok(
            "get_devices_data_usage",
            args(&GET_DEVICES_DATA_USAGE, window_args()),
        )
        .await?;

    assert_eq!(out["window"]["cadence"], "daily");
    assert_eq!(
        out["data"]["values"][0]["mac"], MAC,
        "per-device entries are returned as eero sent them"
    );
    Ok(())
}

#[tokio::test]
async fn get_devices_data_usage_sends_the_profile_filter_only_when_given() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(
        &h,
        &GET_DEVICES_DATA_USAGE,
        &query("hourly", &[("profile_id", "profile-0001")]),
        1,
    )
    .await;

    h.call_ok(
        "get_devices_data_usage",
        args(
            &GET_DEVICES_DATA_USAGE,
            json!({"start": START, "end": END, "cadence": "hourly", "profile_id": "profile-0001"}),
        ),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn every_profile_id_form_reaches_the_filter_as_the_bare_id() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    let forms = [
        json!("profile-0001"),
        json!("  profile-0001  "),
        json!("/2.2/networks/network-0001/profiles/profile-0001"),
        json!("/2.2/networks/network-0001/profiles/profile-0001/"),
        json!(format!(
            "{origin}/2.2/networks/network-0001/profiles/profile-0001"
        )),
    ];
    mount(
        &h,
        &GET_DEVICES_DATA_USAGE,
        &query("daily", &[("profile_id", "profile-0001")]),
        u64::try_from(forms.len())?,
    )
    .await;

    for form in forms {
        h.call_ok(
            "get_devices_data_usage",
            args(
                &GET_DEVICES_DATA_USAGE,
                json!({"start": START, "end": END, "profile_id": form.clone()}),
            ),
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn an_integer_profile_id_is_accepted_and_rendered_in_decimal() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(
        &h,
        &GET_DEVICES_DATA_USAGE,
        &query("daily", &[("profile_id", "12345")]),
        1,
    )
    .await;
    h.call_ok(
        "get_devices_data_usage",
        args(
            &GET_DEVICES_DATA_USAGE,
            json!({"start": START, "end": END, "profile_id": 12345}),
        ),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn a_null_profile_filter_means_omitted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(&h, &GET_DEVICES_DATA_USAGE, &query("daily", &[]), 1).await;
    h.call_ok(
        "get_devices_data_usage",
        args(
            &GET_DEVICES_DATA_USAGE,
            json!({"start": START, "end": END, "profile_id": null}),
        ),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn a_profile_filter_of_another_network_is_rejected_before_any_request() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    let err = h
        .call_err(
            "get_devices_data_usage",
            args(
                &GET_DEVICES_DATA_USAGE,
                json!({"profile_id": "/2.2/networks/network-0009/profiles/profile-0001"}),
            ),
        )
        .await?;

    assert_eq!(err["error"]["code"], "invalid_argument");
    assert_eq!(err["error"]["field"], "profile_id");
    assert!(
        !err["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("network-0009")
    );
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_profile_filter_path_is_checked_against_the_default_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;

    let err = h
        .call_err(
            "get_devices_data_usage",
            args_without_network(
                &GET_DEVICES_DATA_USAGE,
                json!({"profile_id": "/2.2/networks/network-0009/profiles/profile-0001"}),
            ),
        )
        .await?;

    assert_eq!(err["error"]["code"], "invalid_argument");
    assert_eq!(err["error"]["field"], "profile_id");
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks"],
        "the usage read never happens"
    );
    Ok(())
}

// ===================== get_device_data_usage =====================

#[tokio::test]
async fn get_device_data_usage_trims_the_mac_and_keeps_its_spelling() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get_with(
        "/2.2/networks/network-0001/data_usage/devices/AA:BB:CC:00:00:01",
        &default_query(&GET_DEVICE_DATA_USAGE),
        &usage_fixture("device_data_usage"),
        1,
    )
    .await;

    h.call_ok(
        "get_device_data_usage",
        object(json!({
            "network_id": NET,
            "device_mac": "  AA:BB:CC:00:00:01  ",
            "start": START,
            "end": END
        })),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn an_invalid_device_mac_fails_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in [
        "",
        "   ",
        "a/b",
        "../hostile-0001",
        "bad mac",
        "bad\nmac",
        "-leading",
        "has?query",
        "/2.2/networks/network-0001/devices/aa:bb:cc:00:00:01",
    ] {
        let err = h
            .call_err(
                "get_device_data_usage",
                object(json!({"network_id": NET, "device_mac": bad})),
            )
            .await?;
        assert_eq!(err["error"]["code"], "invalid_argument", "{bad:?}");
        assert_eq!(err["error"]["field"], "device_mac", "{bad:?}");
        let message = err["error"]["message"].as_str().unwrap_or_default();
        assert!(!message.is_empty());
        assert!(!message.contains("hostile"), "{bad:?}: {message}");
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_missing_required_id_is_a_deserialisation_failure_with_no_request() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for (name, missing) in [
        ("get_device_data_usage", "device_mac"),
        ("get_profile_data_usage", "profile_id"),
        ("get_device_insights", "device_id"),
    ] {
        let result = h.call(name, object(json!({"network_id": NET}))).await?;
        assert_eq!(result.is_error, Some(true), "{name}");
        let text = result.content[0].as_text().expect("text").text.clone();
        assert!(
            text.starts_with("failed to deserialize parameters"),
            "{text}"
        );
        assert!(text.contains(missing), "{name}: {text}");
    }
    h.assert_no_requests().await;
    Ok(())
}

// ===================== get_profile_data_usage =====================

#[tokio::test]
async fn every_profile_path_form_reads_the_profile_usage() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    let forms = [
        json!("profile-0001"),
        json!("/2.2/networks/network-0001/profiles/profile-0001"),
        json!(format!(
            "{origin}/2.2/networks/network-0001/profiles/profile-0001/"
        )),
    ];
    mount(
        &h,
        &GET_PROFILE_DATA_USAGE,
        &default_query(&GET_PROFILE_DATA_USAGE),
        u64::try_from(forms.len())?,
    )
    .await;

    for form in forms {
        let out = h
            .call_ok(
                "get_profile_data_usage",
                object(json!({
                    "network_id": NET,
                    "profile_id": form.clone(),
                    "start": START,
                    "end": END
                })),
            )
            .await?;
        assert_eq!(out["network_id"], NET, "{form}");
    }
    Ok(())
}

#[tokio::test]
async fn an_invalid_profile_id_fails_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in [
        "",
        "   ",
        "a/b",
        "../hostile-0001",
        "bad id",
        "/2.2/eeros/eero-0001",
        "/2.2/networks/network-0009/profiles/profile-0001",
        "https://api-user.e2ro.com/2.2/networks/network-0001/profiles/profile-0001",
    ] {
        for name in ["get_profile_data_usage", "get_devices_data_usage"] {
            let err = h
                .call_err(name, object(json!({"network_id": NET, "profile_id": bad})))
                .await?;
            assert_eq!(err["error"]["code"], "invalid_argument", "{name} {bad:?}");
            assert_eq!(err["error"]["field"], "profile_id", "{name} {bad:?}");
            let message = err["error"]["message"].as_str().unwrap_or_default();
            for echoed in ["hostile", "network-0009", "e2ro", "eero-0001"] {
                assert!(!message.contains(echoed), "{name} {bad:?}: {message}");
            }
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_profile_path_is_checked_against_the_default_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;

    let err = h
        .call_err(
            "get_profile_data_usage",
            object(json!({"profile_id": "/2.2/networks/network-0009/profiles/profile-0001"})),
        )
        .await?;

    assert_eq!(err["error"]["code"], "invalid_argument");
    assert_eq!(err["error"]["field"], "profile_id");
    assert_eq!(h.targets().await, ["GET /2.2/networks"]);
    Ok(())
}

// ===================== get_eeros_data_usage =====================

#[tokio::test]
async fn get_eeros_data_usage_answering_not_found_means_not_offered() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    authed_get_with(
        GET_EEROS_DATA_USAGE.route,
        &default_query(&GET_EEROS_DATA_USAGE),
    )
    .respond_with(json_status(
        404,
        &json!({"meta": {"code": 404, "error": "error.not.found"}, "data": {}}),
    ))
    .expect(1)
    .mount(&h.mock)
    .await;

    let err = h
        .call_err(
            "get_eeros_data_usage",
            args(&GET_EEROS_DATA_USAGE, window_args()),
        )
        .await?;

    assert_eq!(err["error"]["code"], "not_found");
    assert_eq!(err["error"]["upstream_status"], 404);
    assert!(
        err["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("not supported on this network or firmware")
    );
    Ok(())
}

// ===================== the insights tools =====================

#[tokio::test]
async fn get_insights_sends_the_insight_type_and_the_cadence_in_the_right_names()
-> anyhow::Result<()> {
    // rusteero takes insight_type BEFORE cadence on this read; a swapped call would send
    // cadence=adblock (which rusteero itself refuses) instead of these two values.
    let h = Harness::start().await?;
    mount(
        &h,
        &GET_INSIGHTS,
        &query("hourly", &[("insight_type", "adblock")]),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_insights",
            args(
                &GET_INSIGHTS,
                json!({"start": START, "end": END, "cadence": "hourly", "insight_type": "adblock"}),
            ),
        )
        .await?;

    assert_eq!(
        out["window"],
        json!({"start": START, "end": END, "cadence": "hourly", "insight_type": "adblock"})
    );
    Ok(())
}

#[tokio::test]
async fn the_other_insights_reads_send_the_same_two_values_in_the_right_names() -> anyhow::Result<()>
{
    // These two take cadence BEFORE insight_type.
    for spec in [&GET_DEVICES_INSIGHTS, &GET_DEVICE_INSIGHTS] {
        let h = Harness::start().await?;
        mount(
            &h,
            spec,
            &query("hourly", &[("insight_type", "malware")]),
            1,
        )
        .await;

        let out = h
            .call_ok(
                spec.name,
                args(
                    spec,
                    json!({"start": START, "end": END, "cadence": "hourly", "insight_type": "malware"}),
                ),
            )
            .await?;

        assert_eq!(out["window"]["cadence"], "hourly", "{}", spec.name);
        assert_eq!(out["window"]["insight_type"], "malware", "{}", spec.name);
    }
    Ok(())
}

#[tokio::test]
async fn every_insight_type_is_forwarded_by_every_insights_tool() -> anyhow::Result<()> {
    let types = [
        "inspected",
        "blocked",
        "malware",
        "phishing",
        "botnet",
        "filtered",
        "adult",
        "illegal",
        "violent",
        "adblock",
        "datausage",
    ];
    for spec in INSIGHT_TOOLS {
        let h = Harness::start().await?;
        for insight in types {
            mount(&h, spec, &query("daily", &[("insight_type", insight)]), 1).await;
        }
        for insight in types {
            let out = h
                .call_ok(
                    spec.name,
                    args(
                        spec,
                        json!({"start": START, "end": END, "insight_type": insight}),
                    ),
                )
                .await?;
            assert_eq!(out["window"]["insight_type"], insight, "{}", spec.name);
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_premium_error_on_an_insights_tool_is_premium_required() -> anyhow::Result<()> {
    for spec in INSIGHT_TOOLS {
        let h = Harness::start().await?;
        authed_get_with(spec.route, &default_query(spec))
            .respond_with(json_status(
                403,
                &json!({
                    "meta": {"code": 403, "error": "error.premium.user_not_subscribed"},
                    "data": {}
                }),
            ))
            .expect(1)
            .mount(&h.mock)
            .await;

        let err = h.call_err(spec.name, args(spec, window_args())).await?;

        let error = &err["error"];
        assert_eq!(error["code"], "premium_required", "{}", spec.name);
        assert_eq!(error["upstream_status"], 403, "{}", spec.name);
        assert_eq!(
            error["upstream_code"], "error.premium.user_not_subscribed",
            "{}",
            spec.name
        );
        let rendered = error.to_string();
        for leak in [NET, "127.0.0.1", "/2.2/", TEST_TOKEN] {
            assert!(!rendered.contains(leak), "{}: {leak} leaked", spec.name);
        }
    }
    Ok(())
}

// ===================== get_device_insights: the device id =====================

/// A device path under `network-0001`, as `list_devices` links publish it.
const DEVICE_PATH: &str = "/2.2/networks/network-0001/devices/aa:bb:cc:00:00:01";

#[tokio::test]
async fn every_device_id_form_reaches_the_insights_get_as_the_bare_id() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    let forms = [
        json!(MAC),
        json!(format!("  {MAC}  ")),
        json!(DEVICE_PATH),
        json!(format!("{DEVICE_PATH}/")),
        json!(format!("{origin}{DEVICE_PATH}")),
    ];
    mount(
        &h,
        &GET_DEVICE_INSIGHTS,
        &default_query(&GET_DEVICE_INSIGHTS),
        u64::try_from(forms.len())?,
    )
    .await;

    for form in &forms {
        let out = h
            .call_ok(
                "get_device_insights",
                args(
                    &GET_DEVICE_INSIGHTS,
                    json!({"device_id": form, "start": START, "end": END}),
                ),
            )
            .await?;
        assert_eq!(out["network_id"], NET, "{form}");
    }

    let targets = h.targets().await;
    assert_eq!(targets.len(), forms.len(), "{targets:?}");
    for target in &targets {
        assert!(
            target.starts_with(&format!("GET {}?", GET_DEVICE_INSIGHTS.route)),
            "{target}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn get_device_insights_trims_the_id_and_keeps_the_mac_spelling() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get_with(
        "/2.2/networks/network-0001/insights/devices/AA:BB:CC:00:00:01",
        &default_query(&GET_DEVICE_INSIGHTS),
        &usage_fixture("device_insights"),
        1,
    )
    .await;

    h.call_ok(
        "get_device_insights",
        args(
            &GET_DEVICE_INSIGHTS,
            json!({"device_id": "  AA:BB:CC:00:00:01  ", "start": START, "end": END}),
        ),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn an_integer_device_id_is_accepted_and_rendered_in_decimal() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get_with(
        "/2.2/networks/network-0001/insights/devices/12345",
        &default_query(&GET_DEVICE_INSIGHTS),
        &usage_fixture("device_insights"),
        1,
    )
    .await;

    h.call_ok(
        "get_device_insights",
        args(
            &GET_DEVICE_INSIGHTS,
            json!({"device_id": 12345, "start": START, "end": END}),
        ),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn an_invalid_device_id_fails_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in [
        "",
        "   ",
        "a/b",
        "../hostile-0001",
        "bad id",
        "bad\nid",
        "-leading",
        "has?query",
        "/2.2/networks/network-0001/profiles/profile-0001",
        "/2.2/networks/network-0001/devices",
        "/2.2/networks/network-0001/devices/../hostile-0001",
        "/2.2/networks/network-0001/devices/aa:bb:cc:00:00:01//",
        "/2.2/eeros/eero-0001",
        "/2.2/networks/network-0009/devices/aa:bb:cc:00:00:01",
        "https://api-user.e2ro.com/2.2/networks/network-0001/devices/aa:bb:cc:00:00:01",
        "http://other.test:1234/2.2/networks/network-0001/devices/aa:bb:cc:00:00:01",
    ] {
        let err = h
            .call_err(
                "get_device_insights",
                args(&GET_DEVICE_INSIGHTS, json!({"device_id": bad})),
            )
            .await?;
        assert_eq!(err["error"]["code"], "invalid_argument", "{bad:?}");
        assert_eq!(err["error"]["field"], "device_id", "{bad:?}");
        let message = err["error"]["message"].as_str().unwrap_or_default();
        assert!(!message.is_empty(), "{bad:?}");
        for echoed in [
            "hostile",
            "network-0009",
            "e2ro",
            "other.test",
            "profile-0001",
            "eero-0001",
        ] {
            assert!(!message.contains(echoed), "{bad:?}: {message}");
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_device_path_naming_another_network_is_rejected_without_an_insights_read()
-> anyhow::Result<()> {
    let other = "/2.2/networks/network-0009/devices/aa:bb:cc:00:00:01";

    // An explicit network: nothing at all reaches the wire.
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    let err = h
        .call_err(
            "get_device_insights",
            args(&GET_DEVICE_INSIGHTS, json!({"device_id": other})),
        )
        .await?;
    assert_eq!(err["error"]["code"], "invalid_argument");
    assert_eq!(err["error"]["field"], "device_id");
    let message = err["error"]["message"].as_str().unwrap_or_default();
    assert!(!message.contains("network-0009"), "{message}");
    h.assert_no_requests().await;

    // A defaulted network: the check completes after the network list, still before the read.
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    let err = h
        .call_err(
            "get_device_insights",
            args_without_network(&GET_DEVICE_INSIGHTS, json!({"device_id": other})),
        )
        .await?;
    assert_eq!(err["error"]["code"], "invalid_argument");
    assert_eq!(err["error"]["field"], "device_id");
    assert_eq!(h.targets().await, ["GET /2.2/networks"]);
    Ok(())
}

#[tokio::test]
async fn a_device_path_naming_the_defaulted_network_is_accepted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    mount(
        &h,
        &GET_DEVICE_INSIGHTS,
        &default_query(&GET_DEVICE_INSIGHTS),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_device_insights",
            args_without_network(
                &GET_DEVICE_INSIGHTS,
                json!({"device_id": DEVICE_PATH, "start": START, "end": END}),
            ),
        )
        .await?;

    assert_eq!(out["network_id"], NET);
    let targets = h.targets().await;
    assert_eq!(targets.len(), 2, "{targets:?}");
    assert_eq!(targets[0], "GET /2.2/networks");
    assert!(
        targets[1].starts_with(&format!("GET {}?", GET_DEVICE_INSIGHTS.route)),
        "{}",
        targets[1]
    );
    Ok(())
}

// ===================== get_devices_insights after get_network =====================

/// A synthetic network envelope that publishes an `insights_devices` link.
fn network_publishing(link: &str) -> String {
    json!({
        "meta": {"code": 200, "server_time": "2026-10-23T11:59:50Z"},
        "data": {
            "url": "/2.2/networks/network-0001",
            "name": "Example-Network",
            "resources": {"insights_devices": link}
        }
    })
    .to_string()
}

#[tokio::test]
async fn get_devices_insights_after_get_network_follows_the_published_insights_link()
-> anyhow::Result<()> {
    // rusteero builds this one request from the cached network envelope's published link when
    // get_network ran in the last 60 seconds (every other test starts from an empty cache).
    // Case one publishes the template's own path; case two a different version, which proves the
    // link, not the template, builds the URL.
    for published in [
        "/2.2/networks/network-0001/insights/devices",
        "/2.3/networks/network-0001/insights/devices",
    ] {
        let h = Harness::start().await?;
        h.mount_get(
            "/2.2/networks/network-0001",
            &network_publishing(published),
            1,
        )
        .await;
        h.mount_get_with(
            published,
            &default_query(&GET_DEVICES_INSIGHTS),
            &usage_fixture(GET_DEVICES_INSIGHTS.fixture),
            1,
        )
        .await;

        h.call_ok("get_network", object(json!({"network_id": NET})))
            .await?;
        let out = h
            .call_ok(
                "get_devices_insights",
                args(&GET_DEVICES_INSIGHTS, window_args()),
            )
            .await?;

        assert_eq!(out["network_id"], NET, "{published}");
        let wire = usage_json(GET_DEVICES_INSIGHTS.fixture);
        assert_eq!(out["data"], wire["data"], "{published}");
        let targets = h.targets().await;
        assert_eq!(targets.len(), 2, "{published}: {targets:?}");
        assert_eq!(targets[0], "GET /2.2/networks/network-0001", "{published}");
        assert!(
            targets[1].starts_with(&format!("GET {published}?")),
            "{published}: {}",
            targets[1]
        );
        assert_eq!(
            query_of(&h.received().await[1]),
            BTreeMap::from([
                ("start".to_owned(), START.to_owned()),
                ("end".to_owned(), END.to_owned()),
                ("cadence".to_owned(), "daily".to_owned()),
                ("insight_type".to_owned(), "blocked".to_owned()),
            ]),
            "{published}"
        );
    }
    Ok(())
}

// ===================== the window: default, one bound, order =====================

#[tokio::test]
async fn omitted_bounds_default_to_the_last_seven_days_ending_now() -> anyhow::Result<()> {
    for spec in ALL {
        let h = Harness::start().await?;
        // The window depends on the clock, so this mock pins only the route and credentials; the
        // query is checked below.
        Mock::given(method("GET"))
            .and(path(spec.route))
            .and(user_token_header())
            .and(session_cookie())
            .respond_with(json_response(&usage_fixture(spec.fixture)))
            .expect(1)
            .mount(&h.mock)
            .await;

        let before = Timestamp::now().as_second();
        let out = h.call_ok(spec.name, args(spec, json!({}))).await?;
        let after = Timestamp::now().as_second();

        let name = spec.name;
        let sent = query_of(&h.received().await[0]);
        let expected_keys: BTreeSet<&str> = if spec.insights {
            ["start", "end", "cadence", "insight_type"].into()
        } else {
            ["start", "end", "cadence"].into()
        };
        assert_eq!(
            sent.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            expected_keys,
            "{name}"
        );
        assert_eq!(sent["cadence"], "daily", "{name}");
        let parse = |bound: &str| -> anyhow::Result<i64> {
            anyhow::ensure!(
                bound.len() == 20 && bound.ends_with('Z'),
                "{name}: UTC whole seconds, got {bound}"
            );
            Ok(bound.parse::<Timestamp>()?.as_second())
        };
        let start = parse(&sent["start"])?;
        let end = parse(&sent["end"])?;
        assert_eq!(end - start, WEEK_SECONDS, "{name}: seven days");
        assert!(
            (before - 1..=after + 1).contains(&end),
            "{name}: the window ends now ({end} not in {before}..={after})"
        );
        assert_eq!(out["window"]["start"], sent["start"].as_str(), "{name}");
        assert_eq!(out["window"]["end"], sent["end"].as_str(), "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn one_bound_derives_the_other_seven_days_away() -> anyhow::Result<()> {
    for spec in ALL {
        let h = Harness::start().await?;
        // Only start: end is start plus seven days, rendered in UTC.
        mount(
            &h,
            spec,
            &window_query(
                spec,
                "2026-10-01T00:00:00Z",
                "2026-10-08T00:00:00Z",
                "daily",
            ),
            1,
        )
        .await;
        // Only end: start is end minus seven days.
        mount(
            &h,
            spec,
            &window_query(
                spec,
                "2026-10-08T00:00:00Z",
                "2026-10-15T00:00:00Z",
                "daily",
            ),
            1,
        )
        .await;

        let from_start = h
            .call_ok(
                spec.name,
                args(spec, json!({"start": "2026-10-01T00:00:00Z"})),
            )
            .await?;
        assert_eq!(
            from_start["window"]["start"], "2026-10-01T00:00:00Z",
            "{}",
            spec.name
        );
        assert_eq!(
            from_start["window"]["end"], "2026-10-08T00:00:00Z",
            "{}",
            spec.name
        );

        let from_end = h
            .call_ok(
                spec.name,
                args(spec, json!({"end": "2026-10-15T00:00:00Z"})),
            )
            .await?;
        assert_eq!(
            from_end["window"]["start"], "2026-10-08T00:00:00Z",
            "{}",
            spec.name
        );
        assert_eq!(
            from_end["window"]["end"], "2026-10-15T00:00:00Z",
            "{}",
            spec.name
        );
    }
    Ok(())
}

#[tokio::test]
async fn caller_bounds_are_forwarded_as_written_and_derived_ones_are_utc() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(
        &h,
        &GET_DATA_USAGE,
        &[
            ("start", "2026-10-01T02:00:00+02:00"),
            ("end", "2026-10-08T00:00:00Z"),
            ("cadence", "daily"),
        ],
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_data_usage",
            args(
                &GET_DATA_USAGE,
                json!({"start": "2026-10-01T02:00:00+02:00"}),
            ),
        )
        .await?;

    assert_eq!(out["window"]["start"], "2026-10-01T02:00:00+02:00");
    assert_eq!(out["window"]["end"], "2026-10-08T00:00:00Z");
    Ok(())
}

#[tokio::test]
async fn a_start_not_before_the_end_is_rejected_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for spec in ALL {
        for (start, end) in [
            (END, START),
            (START, START),
            ("2026-10-16T02:00:00+02:00", "2026-10-16T00:00:00Z"),
        ] {
            let err = h
                .call_err(spec.name, args(spec, json!({"start": start, "end": end})))
                .await?;
            assert_eq!(err["error"]["code"], "invalid_argument", "{}", spec.name);
            assert_eq!(err["error"]["field"], "start", "{}", spec.name);
            let message = err["error"]["message"].as_str().unwrap_or_default();
            assert!(!message.contains("2026"), "{}: {message}", spec.name);
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn malformed_timestamps_are_rejected_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    let bad = [
        "yesterday",
        "",
        "2026-10-16",
        "2026-10-16 00:00:00",
        "2026-10-16T00:00:00",
        "2026-13-16T00:00:00Z",
        "1760572800",
    ];
    for spec in ALL {
        for value in bad {
            for field in ["start", "end"] {
                let err = h
                    .call_err(spec.name, args(spec, json!({ field: value })))
                    .await?;
                assert_eq!(
                    err["error"]["code"], "invalid_argument",
                    "{} {field}={value:?}",
                    spec.name
                );
                assert_eq!(
                    err["error"]["field"], field,
                    "{} {field}={value:?}",
                    spec.name
                );
                let message = err["error"]["message"].as_str().unwrap_or_default();
                assert!(!message.contains("yesterday"), "{message}");
            }
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

// ===================== validation happens before the network is resolved =====================

#[tokio::test]
async fn every_input_is_validated_before_the_default_network_is_read() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for spec in ALL {
        let err = h
            .call_err(
                spec.name,
                args_without_network(spec, json!({"start": END, "end": START})),
            )
            .await?;
        assert_eq!(err["error"]["field"], "start", "{}", spec.name);
    }
    // No network_id on any of these: the id is rejected without reading the network list.
    for (name, field, bad) in [
        (
            "get_device_data_usage",
            "device_mac",
            json!({"device_mac": "a/b"}),
        ),
        (
            "get_profile_data_usage",
            "profile_id",
            json!({"profile_id": "a/b"}),
        ),
        (
            "get_devices_data_usage",
            "profile_id",
            json!({"profile_id": "a/b"}),
        ),
        (
            "get_device_insights",
            "device_id",
            json!({"device_id": "a/b"}),
        ),
        (
            "get_device_insights",
            "device_id",
            json!({"device_id": "/2.2/networks/network-0001/profiles/profile-0001"}),
        ),
    ] {
        let err = h.call_err(name, object(bad)).await?;
        assert_eq!(err["error"]["code"], "invalid_argument", "{name}");
        assert_eq!(err["error"]["field"], field, "{name}");
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn invalid_network_ids_fail_before_any_request_on_every_usage_tool() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    let bad_ids = [
        "",
        "   ",
        "../hostile-0001",
        "a/b",
        "bad id",
        "/2.2/eeros/eero-0001",
        "/2.2/networks/network-0001/devices",
        "https://api-user.e2ro.com/2.2/networks/network-0001",
    ];
    for spec in ALL {
        for bad in bad_ids {
            let err = h
                .call_err(spec.name, args(spec, json!({"network_id": bad})))
                .await?;
            assert_eq!(
                err["error"]["code"], "invalid_argument",
                "{} {bad:?}",
                spec.name
            );
            assert_eq!(err["error"]["field"], "network_id", "{} {bad:?}", spec.name);
            let message = err["error"]["message"].as_str().unwrap_or_default();
            for echoed in ["hostile", "e2ro", "eero-0001", "devices"] {
                assert!(
                    !message.contains(echoed),
                    "{} {bad:?}: {message}",
                    spec.name
                );
            }
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn unknown_fields_wrong_types_and_bad_enumerations_never_reach_the_wire() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for spec in ALL {
        let mut bad: Vec<Value> = vec![
            json!({"bogus": 1}),
            // None of the eight is cached.
            json!({"refresh": true}),
            json!({"cadence": "weekly"}),
            json!({"cadence": "Daily"}),
            json!({"cadence": ""}),
            json!({"start": 5}),
            json!({"end": true}),
        ];
        if spec.insights {
            bad.push(json!({"timezone": "UTC"}));
            bad.push(json!({"insight_type": "everything"}));
            bad.push(json!({"insight_type": "Blocked"}));
        } else {
            bad.push(json!({"insight_type": "blocked"}));
            bad.push(json!({"timezone": 5}));
        }
        for extra in bad {
            let result = h.call(spec.name, args(spec, extra.clone())).await?;
            assert_eq!(result.is_error, Some(true), "{} {extra}", spec.name);
            let text = result.content[0].as_text().expect("text").text.clone();
            assert!(
                text.starts_with("failed to deserialize parameters"),
                "{} {extra}: {text}",
                spec.name
            );
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

// ===================== the default network =====================

#[tokio::test]
async fn an_omitted_network_id_uses_the_only_network_on_every_usage_tool() -> anyhow::Result<()> {
    for spec in ALL {
        let h = Harness::start().await?;
        h.mount_single_network(1).await;
        mount(&h, spec, &default_query(spec), 1).await;

        let out = h
            .call_ok(spec.name, args_without_network(spec, window_args()))
            .await?;

        assert_eq!(out["network_id"], NET, "{}", spec.name);
        let targets = h.targets().await;
        assert_eq!(targets.len(), 2, "{}: {targets:?}", spec.name);
        assert_eq!(targets[0], "GET /2.2/networks", "{}", spec.name);
        assert!(
            targets[1].starts_with(&format!("GET {}?", spec.route)),
            "{}: {}",
            spec.name,
            targets[1]
        );
    }
    Ok(())
}

#[tokio::test]
async fn several_networks_without_a_network_id_list_each_id_and_read_no_usage() -> anyhow::Result<()>
{
    for spec in ALL {
        let h = Harness::start().await?;
        common::authed_get("/2.2/networks")
            .respond_with(json_response(
                &json!({
                    "meta": {"code": 200, "server_time": "2026-01-01T00:00:15Z"},
                    "data": [
                        {"url": "/2.2/networks/network-0001", "name": "Example-Network"},
                        {"url": "/2.2/networks/network-0002", "name": "Second-Network"}
                    ]
                })
                .to_string(),
            ))
            .expect(1)
            .mount(&h.mock)
            .await;

        let err = h
            .call_err(spec.name, args_without_network(spec, window_args()))
            .await?;

        assert_eq!(err["error"]["code"], "invalid_argument", "{}", spec.name);
        assert_eq!(err["error"]["field"], "network_id", "{}", spec.name);
        let message = err["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("network-0001 (Example-Network)"),
            "{message}"
        );
        assert!(
            message.contains("network-0002 (Second-Network)"),
            "{message}"
        );
        assert_eq!(h.targets().await, ["GET /2.2/networks"], "{}", spec.name);
    }
    Ok(())
}

#[tokio::test]
async fn an_explicit_network_id_never_reads_the_network_list() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    mount(
        &h,
        &GET_EEROS_DATA_USAGE,
        &default_query(&GET_EEROS_DATA_USAGE),
        1,
    )
    .await;
    h.call_ok(
        "get_eeros_data_usage",
        args(&GET_EEROS_DATA_USAGE, window_args()),
    )
    .await?;
    let targets = h.targets().await;
    assert_eq!(targets.len(), 1);
    assert!(targets[0].starts_with("GET /2.2/networks/network-0001/data_usage/eeros?"));
    Ok(())
}

#[tokio::test]
async fn every_network_id_form_reaches_the_same_usage_get() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    let forms = [
        json!("network-0001"),
        json!("  network-0001  "),
        json!("/2.2/networks/network-0001"),
        json!("/2.2/networks/network-0001/"),
        json!(format!("{origin}/2.2/networks/network-0001")),
    ];
    mount(
        &h,
        &GET_DATA_USAGE,
        &default_query(&GET_DATA_USAGE),
        u64::try_from(forms.len())?,
    )
    .await;

    for form in forms {
        let out = h
            .call_ok(
                "get_data_usage",
                object(json!({"network_id": form.clone(), "start": START, "end": END})),
            )
            .await?;
        assert_eq!(out["network_id"], NET, "{form}");
    }
    Ok(())
}

// ===================== no cache, redaction =====================

#[tokio::test]
async fn a_repeat_call_is_a_new_request_because_nothing_here_is_cached() -> anyhow::Result<()> {
    for spec in ALL {
        let h = Harness::start().await?;
        mount(&h, spec, &default_query(spec), 2).await;
        for _ in 0..2 {
            h.call_ok(spec.name, args(spec, window_args())).await?;
        }
        assert_eq!(h.targets().await.len(), 2, "{}", spec.name);
    }
    Ok(())
}

#[tokio::test]
async fn a_secret_key_anywhere_in_a_usage_response_is_redacted() -> anyhow::Result<()> {
    for spec in ALL {
        let h = Harness::start().await?;
        let body = json!({
            "meta": {"code": 200, "server_time": "2026-10-23T12:00:00Z"},
            "data": {
                "series": [{"sum": 1, "token": "secret0000", "values": []}],
                "password": "hunter2",
                "name": "kept",
                "psk": ""
            }
        });
        h.mount_get_with(spec.route, &default_query(spec), &body.to_string(), 1)
            .await;

        let out = h.call_ok(spec.name, args(spec, window_args())).await?;

        assert_eq!(out["data"]["series"][0]["token"], REDACTED, "{}", spec.name);
        assert_eq!(out["data"]["password"], REDACTED, "{}", spec.name);
        assert_eq!(out["data"]["name"], "kept", "{}", spec.name);
        assert_eq!(out["data"]["psk"], "", "empty values stay visible");
        let rendered = out.to_string();
        for secret in ["secret0000", "hunter2"] {
            assert!(!rendered.contains(secret), "{}: {secret} leaked", spec.name);
        }
    }
    Ok(())
}

#[tokio::test]
async fn eero_rejecting_a_timezone_surfaces_as_invalid_argument_without_a_field()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    authed_get_with(
        GET_DATA_USAGE.route,
        &query("daily", &[("timezone", "Not/AZone")]),
    )
    .respond_with(json_status(
        400,
        &json!({"meta": {"code": 400, "error": "error.form.errors"}, "data": {}}),
    ))
    .expect(1)
    .mount(&h.mock)
    .await;

    let err = h
        .call_err(
            "get_data_usage",
            args(
                &GET_DATA_USAGE,
                json!({"start": START, "end": END, "timezone": "Not/AZone"}),
            ),
        )
        .await?;

    assert_eq!(err["error"]["code"], "invalid_argument");
    assert!(err["error"].get("field").is_none());
    assert_eq!(err["error"]["upstream_code"], "error.form.errors");
    Ok(())
}
