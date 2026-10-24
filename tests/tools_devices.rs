//! Pins the devices-group tools (11 to 14): the listing and annotations, the exact GET path and
//! query, both credentials, the output shape, the `list_devices` summary projection (only present
//! keys, the id from the url tail, nested reductions, unknown keys dropped) and `detail: full`,
//! cache and refresh call counts, every device id form including MAC spellings and path or URL
//! membership, default-network resolution, the `get_transfer_stats` 403 nuance, and validation
//! before any request.

mod common;

use common::{Harness, authed_get, fixture, fixture_json, json_response, json_status};
use rmcp::model::Tool;
use rmcp::object;
use serde_json::{Value, json};

const GROUP: &str = "devices";
const REDACTED: &str = "[REDACTED]";

fn devices_fixture(name: &str) -> String {
    fixture(GROUP, name)
}

fn devices_json(name: &str) -> Value {
    fixture_json(GROUP, name)
}

fn tool<'a>(tools: &'a [Tool], name: &str) -> &'a Tool {
    tools
        .iter()
        .find(|tool| tool.name == name)
        .unwrap_or_else(|| panic!("tool {name} is not listed"))
}

fn has_property(tool: &Tool, property: &str) -> bool {
    tool.input_schema
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| properties.contains_key(property))
}

/// No path, host, id or token may reach the client in a tool error.
fn assert_clean(error: &Value) {
    let rendered = error.to_string();
    for leak in [
        "127.0.0.1",
        "localhost",
        "network-0001",
        "device-0001",
        "/2.2/",
        "hunter2",
        "test-token",
    ] {
        assert!(!rendered.contains(leak), "{leak:?} leaked into {rendered}");
    }
}

const DEVICE_TOOLS: [&str; 4] = [
    "list_devices",
    "get_device",
    "list_blocked_devices",
    "get_transfer_stats",
];

const LIST_ROUTE: &str = "/2.2/networks/network-0001/devices";
const DEVICE_ROUTE: &str = "/2.2/networks/network-0001/devices/device-0001";

/// A network list with two networks, for the ambiguous default-network case.
fn two_networks() -> String {
    json!({
        "meta": {"code": 200, "server_time": "2026-01-01T00:00:15Z"},
        "data": [
            {"url": "/2.2/networks/network-0001", "name": "Example-Network"},
            {"url": "/2.2/networks/network-0002", "name": "Second-Network"}
        ]
    })
    .to_string()
}

/// The three fixture devices as the summary must project them: `devices.json`, reduced.
fn expected_summaries() -> Value {
    json!([
        {
            "id": "device-0001",
            "url": "/2.2/networks/network-0001/devices/device-0001",
            "mac": "aa:bb:cc:00:00:01",
            "nickname": "Example Phone",
            "hostname": "example-phone",
            "display_name": "Example Phone",
            "manufacturer": "Example Manufacturer",
            "device_type": "phone",
            "model_name": "Example Phone 1",
            "ip": "192.0.2.101",
            "ips": ["192.0.2.101"],
            "connected": true,
            "wireless": true,
            "connection_type": "wireless",
            "interface": {"frequency": "5", "frequency_unit": "GHz"},
            "source": {"location": "Living Room", "url": "/2.2/eeros/eero-0001"},
            "profile": {
                "name": "Adults",
                "url": "/2.2/networks/network-0001/profiles/profile-0001"
            },
            "blacklisted": false,
            "paused": false,
            "prioritized": false,
            "is_guest": false,
            "first_active": "2025-12-01T08:00:00Z",
            "last_active": "2026-01-01T00:00:00Z"
        },
        {
            "id": "explicit-0002",
            "url": "/2.2/networks/network-0001/devices/device-0002",
            "mac": "aa:bb:cc:00:00:02",
            "nickname": null,
            "hostname": "example-laptop",
            "manufacturer": "Other Manufacturer",
            "ip": "192.0.2.102",
            "connected": true,
            "wireless": false,
            "connection_type": "wired",
            "source": {"location": "Living Room", "url": "/2.2/eeros/eero-0001"},
            "profile": null,
            "blocked": false,
            "prioritized": true
        },
        {
            "id": "aabbcc000003",
            "url": "/2.2/networks/network-0001/devices/aabbcc000003",
            "mac": "aa:bb:cc:00:00:03",
            "hostname": "example-sensor",
            "ip": "192.0.2.103",
            "connected": false,
            "wireless": true,
            "connection_type": "wireless",
            "interface": {"frequency": "2.4", "frequency_unit": "GHz"},
            "source": {"location": "Bedroom", "url": "/2.2/eeros/eero-0002"},
            "profile": {
                "name": "Guests",
                "url": "/2.2/networks/network-0001/profiles/profile-0002"
            },
            "blacklisted": true,
            "paused": true,
            "is_guest": true,
            "last_active": "2025-12-31T23:00:00Z"
        }
    ])
}

// ===================== the listed tools =====================

#[tokio::test]
async fn the_four_device_tools_are_listed_read_only_with_titles_and_output_schemas()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for name in DEVICE_TOOLS {
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
        assert!(description.len() > 40, "{name} has a real description");
        assert!(listed.output_schema.is_some(), "{name} has an outputSchema");
        assert_eq!(
            listed.input_schema.get("additionalProperties"),
            Some(&json!(false)),
            "{name} rejects unknown fields"
        );
        assert!(has_property(listed, "network_id"), "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn the_device_tools_publish_their_documented_inputs() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    // refresh: only the two cached reads.
    for (name, cached) in [
        ("list_devices", true),
        ("get_device", true),
        ("list_blocked_devices", false),
        ("get_transfer_stats", false),
    ] {
        assert_eq!(
            has_property(tool(&tools, name), "refresh"),
            cached,
            "{name}"
        );
    }

    // detail: list_devices only, a closed enumeration.
    let list = tool(&tools, "list_devices");
    assert_eq!(
        list.input_schema["properties"]["detail"]["enum"],
        json!(["summary", "full"])
    );
    assert!(list.input_schema.get("required").is_none());
    for name in ["get_device", "list_blocked_devices", "get_transfer_stats"] {
        assert!(!has_property(tool(&tools, name), "detail"), "{name}");
    }
    // The thread and proxied-node filters of the underlying read are not exposed.
    for property in ["thread", "proxied_node"] {
        assert!(!has_property(list, property), "{property}");
    }

    // get_device: a required device_id. get_transfer_stats: an optional one.
    let device = tool(&tools, "get_device");
    assert_eq!(device.input_schema["required"], json!(["device_id"]));
    assert_eq!(
        device.input_schema["properties"]["device_id"]["type"],
        "string"
    );
    let transfer = tool(&tools, "get_transfer_stats");
    assert!(has_property(transfer, "device_id"));
    assert!(transfer.input_schema.get("required").is_none());
    assert_eq!(
        transfer.input_schema["properties"]["device_id"]["type"],
        "string"
    );
    for name in ["list_devices", "list_blocked_devices"] {
        assert!(!has_property(tool(&tools, name), "device_id"), "{name}");
    }
    Ok(())
}

// ===================== list_devices: the summary =====================

#[tokio::test]
async fn list_devices_summarises_by_default_and_reports_detail_and_count() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices"), 1)
        .await;

    let out = h
        .call_ok("list_devices", object!({"network_id": "network-0001"}))
        .await?;

    let wire = devices_json("devices");
    assert_eq!(out["data"], expected_summaries());
    assert_eq!(out["detail"], "summary");
    assert_eq!(out["count"], 3);
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(
        out.as_object().map(|o| {
            let mut keys: Vec<_> = o.keys().cloned().collect();
            keys.sort();
            keys
        }),
        Some(
            ["count", "data", "detail", "network_id", "server_time"]
                .map(str::to_owned)
                .to_vec()
        ),
        "only the documented members"
    );
    // The query is pinned to exactly nothing: neither rusteero filter is ever sent.
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/devices"]
    );
    Ok(())
}

#[tokio::test]
async fn the_summary_emits_only_the_keys_a_device_has() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices"), 1)
        .await;

    let out = h
        .call_ok("list_devices", object!({"network_id": "network-0001"}))
        .await?;

    let devices = out["data"].as_array().expect("array");
    let keys = |index: usize| -> Vec<&str> {
        devices[index]
            .as_object()
            .expect("object")
            .keys()
            .map(String::as_str)
            .collect()
    };
    // The third device has no nickname, display_name, manufacturer or prioritized: none appears.
    for absent in [
        "nickname",
        "display_name",
        "manufacturer",
        "prioritized",
        "blocked",
    ] {
        assert!(!keys(2).contains(&absent), "{absent} was not on the device");
    }
    // The first has no `blocked` key (it uses `blacklisted`), the second has no `blacklisted`.
    assert!(!keys(0).contains(&"blocked"));
    assert!(!keys(1).contains(&"blacklisted"));
    // A present null is a present key: it is copied, not dropped.
    assert_eq!(devices[1].get("nickname"), Some(&Value::Null));
    assert_eq!(devices[1].get("profile"), Some(&Value::Null));
    // `blocked` and `blacklisted` each travel under their own key, never merged.
    assert_eq!(devices[0]["blacklisted"], false);
    assert_eq!(devices[1]["blocked"], false);
    assert_eq!(devices[2]["blacklisted"], true);
    Ok(())
}

#[tokio::test]
async fn the_summary_takes_the_id_from_the_url_tail_unless_the_device_has_one() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices"), 1)
        .await;

    let out = h
        .call_ok("list_devices", object!({"network_id": "network-0001"}))
        .await?;

    assert_eq!(out["data"][0]["id"], "device-0001", "tail of the url");
    assert_eq!(out["data"][1]["id"], "explicit-0002", "an id field wins");
    assert_eq!(out["data"][2]["id"], "aabbcc000003", "tail of the url");
    Ok(())
}

#[tokio::test]
async fn the_summary_reduces_nested_objects_and_drops_unknown_keys() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices"), 1)
        .await;

    let out = h
        .call_ok("list_devices", object!({"network_id": "network-0001"}))
        .await?;

    let first = &out["data"][0];
    // interface keeps the band only; source keeps location and url; profile keeps name and url.
    assert_eq!(
        first["interface"],
        json!({"frequency": "5", "frequency_unit": "GHz"})
    );
    assert_eq!(
        first["source"],
        json!({"location": "Living Room", "url": "/2.2/eeros/eero-0001"})
    );
    assert_eq!(
        first["profile"],
        json!({
            "name": "Adults",
            "url": "/2.2/networks/network-0001/profiles/profile-0001"
        })
    );
    // Everything else eero sent for the device is gone.
    for dropped in [
        "model",
        "ipv4",
        "ssid",
        "is_private",
        "usage",
        "connectivity",
        "auth",
    ] {
        for device in out["data"].as_array().expect("array") {
            assert!(device.get(dropped).is_none(), "{dropped} should be dropped");
        }
    }
    // An interface with nothing worth emitting is left out rather than emitted empty.
    assert!(out["data"][1].get("interface").is_none());
    let rendered = out.to_string();
    for dropped in ["rx_rate", "is_proxied_node", "down_mbps", "score_bars"] {
        assert!(!rendered.contains(dropped), "{dropped} leaked");
    }
    Ok(())
}

#[tokio::test]
async fn the_summary_is_much_smaller_than_the_full_list() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices"), 1)
        .await;
    let summary = h
        .call_ok("list_devices", object!({"network_id": "network-0001"}))
        .await?;
    let full = h
        .call_ok(
            "list_devices",
            object!({"network_id": "network-0001", "detail": "full"}),
        )
        .await?;
    assert!(
        summary["data"].to_string().len() < full["data"].to_string().len(),
        "the projection exists to keep the answer small"
    );
    Ok(())
}

#[tokio::test]
async fn an_explicit_summary_equals_the_default() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices"), 1)
        .await;

    let default = h
        .call_ok("list_devices", object!({"network_id": "network-0001"}))
        .await?;
    let explicit = h
        .call_ok(
            "list_devices",
            object!({"network_id": "network-0001", "detail": "summary"}),
        )
        .await?;

    assert_eq!(default, explicit);
    Ok(())
}

// ===================== list_devices: detail full =====================

#[tokio::test]
async fn detail_full_returns_the_raw_device_array() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices"), 1)
        .await;

    let out = h
        .call_ok(
            "list_devices",
            object!({"network_id": "network-0001", "detail": "full"}),
        )
        .await?;

    let wire = devices_json("devices");
    assert_eq!(
        out["data"], wire["data"],
        "no deny-listed key in this fixture"
    );
    assert_eq!(out["detail"], "full");
    assert_eq!(out["count"], 3);
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    // The keys the summary drops are all here.
    assert_eq!(out["data"][0]["usage"]["down_mbps"], 1.5);
    assert_eq!(out["data"][0]["ssid"], "Example-Network");
    assert_eq!(out["data"][0]["interface"]["rx_rate"], "866");
    assert!(out["data"][0].get("id").is_none(), "no id is invented");
    Ok(())
}

#[tokio::test]
async fn detail_is_a_closed_enumeration() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    for detail in ["brief", "Full", "SUMMARY", "", "all"] {
        let result = h
            .call(
                "list_devices",
                object!({"network_id": "network-0001", "detail": detail}),
            )
            .await?;
        assert_eq!(result.is_error, Some(true), "{detail:?}");
        let text = result.content[0].as_text().expect("text").text.clone();
        assert!(
            text.starts_with("failed to deserialize parameters"),
            "{text}"
        );
    }
    h.assert_no_requests().await;
    Ok(())
}

// ===================== list_devices: other list shapes =====================

#[tokio::test]
async fn a_list_wrapped_under_devices_is_summarised() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices_wrapped"), 2)
        .await;

    let summary = h
        .call_ok(
            "list_devices",
            object!({"network_id": "network-0001", "refresh": true}),
        )
        .await?;
    assert_eq!(
        summary["data"],
        json!([{
            "id": "device-0001",
            "url": "/2.2/networks/network-0001/devices/device-0001",
            "mac": "aa:bb:cc:00:00:01",
            "hostname": "example-phone",
            "connected": true
        }])
    );
    assert_eq!(summary["detail"], "summary");
    assert_eq!(summary["count"], 1);

    // Full mode returns the raw device array too, not eero's container.
    let full = h
        .call_ok(
            "list_devices",
            object!({"network_id": "network-0001", "refresh": true, "detail": "full"}),
        )
        .await?;
    assert_eq!(
        full["data"],
        json!([devices_json("devices_wrapped")["data"]["devices"][0].clone()])
    );
    assert!(full["data"].is_array());
    assert_eq!(full["data"][0]["internal_note"], "dropped");
    assert_eq!(full["detail"], "full");
    assert_eq!(full["count"], 1);
    Ok(())
}

#[tokio::test]
async fn an_empty_device_list_is_an_empty_list_in_both_modes() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices_empty"), 2)
        .await;

    for (args, detail) in [
        (
            object!({"network_id": "network-0001", "refresh": true}),
            "summary",
        ),
        (
            object!({"network_id": "network-0001", "refresh": true, "detail": "full"}),
            "full",
        ),
    ] {
        let out = h.call_ok("list_devices", args).await?;
        assert_eq!(out["data"], json!([]), "{detail}");
        assert_eq!(out["count"], 0, "{detail}");
        assert_eq!(out["detail"], detail);
    }
    Ok(())
}

#[tokio::test]
async fn a_summary_over_an_unrecognised_shape_falls_back_to_the_raw_redacted_data()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices_unrecognised"), 1)
        .await;

    let out = h
        .call_ok("list_devices", object!({"network_id": "network-0001"}))
        .await?;

    // Not zero devices: the raw data, redacted, and detail names what data holds.
    assert_eq!(
        out["data"],
        json!({"message": "no device list here", "token": REDACTED})
    );
    assert_eq!(out["detail"], "full");
    assert!(
        out.get("count").is_none(),
        "no recognisable list: no count, 0 would claim an empty network"
    );
    assert!(!out.to_string().contains("devicetoken000"));
    Ok(())
}

#[tokio::test]
async fn list_devices_redacts_secrets_in_summary_and_full_mode() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // Synthetic secrets under deny-listed keys: a device-level key the summary drops, and nested
    // values the summary copies verbatim (`ips`, a non-object `profile`).
    let body = json!({
        "meta": {"code": 200, "server_time": "2026-01-01T00:00:15Z"},
        "data": [{
            "url": "/2.2/networks/network-0001/devices/device-0001",
            "mac": "aa:bb:cc:00:00:01",
            "hostname": "example-host",
            "password": "devicepass000",
            "ips": [{"ip": "192.0.2.101", "psk": "ippsk000"}],
            "profile": [{"name": "Adults", "token": "profiletoken000"}],
            "source": "plain-source"
        }]
    })
    .to_string();
    h.mount_get(LIST_ROUTE, &body, 2).await;
    let secrets = ["devicepass000", "ippsk000", "profiletoken000"];

    let summary = h
        .call_ok_hiding(
            "list_devices",
            object!({"network_id": "network-0001", "refresh": true}),
            &secrets,
        )
        .await?;
    assert_eq!(summary["detail"], "summary");
    assert_eq!(summary["data"][0]["ips"][0]["psk"], REDACTED);
    assert_eq!(summary["data"][0]["ips"][0]["ip"], "192.0.2.101");
    assert_eq!(summary["data"][0]["profile"][0]["token"], REDACTED);
    assert_eq!(summary["data"][0]["profile"][0]["name"], "Adults");
    assert_eq!(summary["data"][0]["source"], "plain-source");
    assert!(
        summary["data"][0].get("password").is_none(),
        "the summary does not copy this key at all"
    );

    let full = h
        .call_ok_hiding(
            "list_devices",
            object!({"network_id": "network-0001", "refresh": true, "detail": "full"}),
            &secrets,
        )
        .await?;
    assert_eq!(full["detail"], "full");
    assert_eq!(full["data"][0]["password"], REDACTED);
    assert_eq!(full["data"][0]["ips"][0]["psk"], REDACTED);
    assert_eq!(full["data"][0]["profile"][0]["token"], REDACTED);
    assert_eq!(full["data"][0]["hostname"], "example-host");
    Ok(())
}

#[tokio::test]
async fn the_other_device_reads_redact_secrets_too() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let body = |data: Value| {
        json!({"meta": {"code": 200, "server_time": "2026-01-01T00:00:15Z"}, "data": data})
            .to_string()
    };
    h.mount_get(
        DEVICE_ROUTE,
        &body(json!({"hostname": "example-host", "password": "devicepass000"})),
        1,
    )
    .await;
    h.mount_get(
        "/2.2/networks/network-0001/blacklist",
        &body(json!([{"mac": "aa:bb:cc:00:00:01", "token": "blocktoken000"}])),
        1,
    )
    .await;

    let device = h
        .call_ok_hiding(
            "get_device",
            object!({"network_id": "network-0001", "device_id": "device-0001"}),
            &["devicepass000"],
        )
        .await?;
    assert_eq!(device["data"]["password"], REDACTED);
    assert_eq!(device["data"]["hostname"], "example-host");

    let blocked = h
        .call_ok_hiding(
            "list_blocked_devices",
            object!({"network_id": "network-0001"}),
            &["blocktoken000"],
        )
        .await?;
    assert_eq!(blocked["data"][0]["token"], REDACTED);
    assert_eq!(blocked["data"][0]["mac"], "aa:bb:cc:00:00:01");
    Ok(())
}

// ===================== list_devices: cache, default network, validation =====================

#[tokio::test]
async fn list_devices_serves_a_repeat_from_cache_and_refresh_bypasses_it() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // The first call and the refresh; the repeats in between are cache hits, whatever the detail.
    h.mount_get(LIST_ROUTE, &devices_fixture("devices"), 2)
        .await;

    for args in [
        object!({"network_id": "network-0001"}),
        object!({"network_id": "network-0001", "detail": "full"}),
        object!({"network_id": "network-0001", "refresh": false}),
        object!({"network_id": "network-0001", "refresh": true}),
        object!({"network_id": "network-0001", "detail": "full"}),
    ] {
        h.call_ok("list_devices", args).await?;
    }
    assert_eq!(h.targets().await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn list_devices_without_a_network_id_uses_the_only_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get(LIST_ROUTE, &devices_fixture("devices"), 1)
        .await;

    let out = h.call_ok("list_devices", object!({})).await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["count"], 3);
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks",
            "GET /2.2/networks/network-0001/devices"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn list_devices_rejects_bad_input_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in ["", "   ", "../hostile-0001", "/2.2/eeros/eero-0001"] {
        let err = h
            .call_err("list_devices", object!({"network_id": bad}))
            .await?;
        assert_eq!(err["error"]["code"], "invalid_argument", "{bad:?}");
        assert_eq!(err["error"]["field"], "network_id", "{bad:?}");
        let message = err["error"]["message"].as_str().unwrap_or_default();
        assert!(!message.contains("hostile"), "{message}");
    }
    for args in [
        object!({"thread": true}),
        object!({"proxied_node": false}),
        object!({"device_id": "device-0001"}),
        object!({"refresh": "yes"}),
        object!({"bogus": 1}),
    ] {
        let result = h.call("list_devices", args.clone()).await?;
        assert_eq!(result.is_error, Some(true), "{args:?}");
        let text = result.content[0].as_text().expect("text").text.clone();
        assert!(
            text.starts_with("failed to deserialize parameters"),
            "{text}"
        );
    }
    h.assert_no_requests().await;
    Ok(())
}

// ===================== get_device =====================

#[tokio::test]
async fn get_device_reads_the_device_path_and_echoes_the_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(DEVICE_ROUTE, &devices_fixture("device"), 1)
        .await;

    let out = h
        .call_ok(
            "get_device",
            object!({"network_id": "network-0001", "device_id": "device-0001"}),
        )
        .await?;

    let wire = devices_json("device");
    assert_eq!(
        out["data"], wire["data"],
        "no deny-listed key in this fixture"
    );
    assert_eq!(out["data"]["usage"]["up_mbps"], 0.5, "the full object");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert!(out.get("detail").is_none() && out.get("count").is_none());
    assert_eq!(h.targets().await, [format!("GET {DEVICE_ROUTE}")]);
    Ok(())
}

#[tokio::test]
async fn get_device_serves_a_repeat_from_cache_and_refresh_bypasses_it() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(DEVICE_ROUTE, &devices_fixture("device"), 2)
        .await;

    for args in [
        object!({"network_id": "network-0001", "device_id": "device-0001"}),
        object!({"network_id": "network-0001", "device_id": "device-0001"}),
        object!({"network_id": "network-0001", "device_id": "device-0001", "refresh": true}),
        object!({"network_id": "network-0001", "device_id": "device-0001", "refresh": false}),
    ] {
        h.call_ok("get_device", args).await?;
    }
    assert_eq!(h.targets().await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn get_device_without_a_network_id_uses_the_only_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get(DEVICE_ROUTE, &devices_fixture("device"), 1)
        .await;

    let out = h
        .call_ok("get_device", object!({"device_id": "device-0001"}))
        .await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks".to_owned(),
            format!("GET {DEVICE_ROUTE}")
        ]
    );
    Ok(())
}

#[tokio::test]
async fn every_device_id_form_reaches_the_same_get() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    let forms = [
        json!("device-0001"),
        json!("  device-0001  "),
        json!(DEVICE_ROUTE),
        json!(format!("{DEVICE_ROUTE}/")),
        json!("/2.3/networks/network-0001/devices/device-0001"),
        json!(format!("{origin}{DEVICE_ROUTE}")),
        json!(format!("{origin}{DEVICE_ROUTE}/")),
    ];
    h.mount_get(
        DEVICE_ROUTE,
        &devices_fixture("device"),
        u64::try_from(forms.len())?,
    )
    .await;

    for form in forms {
        // refresh forces a request per form, so each form's request is pinned.
        let out = h
            .call_ok(
                "get_device",
                object!({
                    "network_id": "network-0001",
                    "device_id": form.clone(),
                    "refresh": true
                }),
            )
            .await?;
        assert_eq!(out["network_id"], "network-0001", "{form}");
    }
    assert!(
        h.targets()
            .await
            .iter()
            .all(|target| *target == format!("GET {DEVICE_ROUTE}"))
    );
    Ok(())
}

#[tokio::test]
async fn equivalent_device_id_forms_share_one_cache_entry() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    h.mount_get(DEVICE_ROUTE, &devices_fixture("device"), 1)
        .await;

    for form in [
        "device-0001".to_owned(),
        DEVICE_ROUTE.to_owned(),
        format!("{origin}{DEVICE_ROUTE}"),
        format!("{DEVICE_ROUTE}/"),
        " device-0001 ".to_owned(),
    ] {
        h.call_ok(
            "get_device",
            object!({"network_id": "network-0001", "device_id": form}),
        )
        .await?;
    }
    assert_eq!(
        h.targets().await.len(),
        1,
        "canonical ids hit one cache entry"
    );
    Ok(())
}

#[tokio::test]
async fn an_integer_device_id_is_accepted_and_rendered_in_decimal() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/devices/12345",
        &devices_fixture("device"),
        1,
    )
    .await;
    h.call_ok(
        "get_device",
        object!({"network_id": "network-0001", "device_id": 12345}),
    )
    .await?;
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/devices/12345"]
    );
    Ok(())
}

/// The ways a MAC address is commonly written; all pass the identifier rule.
const MAC_SPELLINGS: [&str; 5] = [
    "aa:bb:cc:00:00:01",
    "AA:BB:CC:00:00:01",
    "aa-bb-cc-00-00-01",
    "aabb.cc00.0001",
    "aabbcc000001",
];

#[tokio::test]
async fn every_mac_spelling_is_sent_as_written() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    for spelling in MAC_SPELLINGS {
        h.mount_get(
            &format!("/2.2/networks/network-0001/devices/{spelling}"),
            &devices_fixture("device"),
            1,
        )
        .await;
    }

    for spelling in MAC_SPELLINGS {
        let out = h
            .call_ok(
                "get_device",
                object!({
                    "network_id": "network-0001",
                    "device_id": spelling,
                    "refresh": true
                }),
            )
            .await?;
        assert_eq!(out["network_id"], "network-0001", "{spelling}");
    }
    assert_eq!(
        h.targets().await,
        MAC_SPELLINGS.map(|spelling| format!("GET /2.2/networks/network-0001/devices/{spelling}"))
    );
    Ok(())
}

#[tokio::test]
async fn every_mac_spelling_shares_one_cache_entry() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // Only the first spelling may reach the wire; the others are the same device.
    h.mount_get(
        "/2.2/networks/network-0001/devices/aa:bb:cc:00:00:01",
        &devices_fixture("device"),
        1,
    )
    .await;

    for spelling in MAC_SPELLINGS {
        h.call_ok(
            "get_device",
            object!({"network_id": "network-0001", "device_id": spelling}),
        )
        .await?;
    }
    h.call_ok(
        "get_device",
        object!({"network_id": "network-0001", "device_id": "  AA:BB:CC:00:00:01  "}),
    )
    .await?;
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/devices/aa:bb:cc:00:00:01"]
    );
    Ok(())
}

#[tokio::test]
async fn a_device_path_naming_another_network_is_rejected_without_a_device_read()
-> anyhow::Result<()> {
    let other = "/2.2/networks/network-0002/devices/device-0001";

    // An explicit network: nothing at all reaches the wire.
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    let err = h
        .call_err(
            "get_device",
            object!({"network_id": "network-0001", "device_id": other}),
        )
        .await?;
    assert_eq!(err["error"]["code"], "invalid_argument");
    assert_eq!(err["error"]["field"], "device_id");
    let message = err["error"]["message"].as_str().unwrap_or_default();
    assert!(!message.contains("network-0002"), "{message}");
    h.assert_no_requests().await;

    // A defaulted network: the check completes after the network list, still before the read.
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    let err = h
        .call_err("get_device", object!({"device_id": other}))
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
    h.mount_get(DEVICE_ROUTE, &devices_fixture("device"), 1)
        .await;

    let out = h
        .call_ok("get_device", object!({"device_id": DEVICE_ROUTE}))
        .await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks".to_owned(),
            format!("GET {DEVICE_ROUTE}")
        ]
    );
    Ok(())
}

#[tokio::test]
async fn invalid_device_ids_fail_before_any_request_on_get_device_and_get_transfer_stats()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    let bad_ids = [
        "",
        "   ",
        "../hostile-0001",
        "a/b",
        "bad id",
        "bad\nid",
        "-leading",
        "has?query",
        "/2.2/networks/network-0001/profiles/profile-0001",
        "/2.2/networks/network-0001/devices",
        "/2.2/networks/network-0001/devices/device-0001/transfer",
        "/2.2/networks/network-0001/devices/../hostile-0001",
        "/2.2/networks/network-0001/devices/device-0001//",
        "/2.2/eeros/eero-0001",
        "https://api-user.e2ro.com/2.2/networks/network-0001/devices/device-0001",
        "http://other.test:1234/2.2/networks/network-0001/devices/device-0001",
    ];
    for name in ["get_device", "get_transfer_stats"] {
        for bad in bad_ids {
            let err = h
                .call_err(
                    name,
                    object!({"network_id": "network-0001", "device_id": bad}),
                )
                .await?;
            assert_eq!(err["error"]["code"], "invalid_argument", "{name} {bad:?}");
            assert_eq!(err["error"]["field"], "device_id", "{name} {bad:?}");
            let message = err["error"]["message"].as_str().unwrap_or_default();
            assert!(!message.is_empty());
            for echoed in ["hostile", "other.test", "e2ro", "profile-0001", "eero-0001"] {
                assert!(!message.contains(echoed), "{name} {bad:?}: {message}");
            }
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_bad_network_id_fails_before_any_request_on_blacklist_and_transfer() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for (name, args) in [
        (
            "list_blocked_devices",
            object!({"network_id": "../hostile-0001"}),
        ),
        (
            "list_blocked_devices",
            object!({"network_id": "/2.2/eeros/eero-0001"}),
        ),
        ("get_transfer_stats", object!({"network_id": "   "})),
        (
            "get_transfer_stats",
            // Both ids are invalid: network_id is reported first.
            object!({"network_id": "../hostile-0001", "device_id": "../hostile-0002"}),
        ),
    ] {
        let err = h.call_err(name, args.clone()).await?;
        assert_eq!(err["error"]["code"], "invalid_argument", "{name} {args:?}");
        assert_eq!(err["error"]["field"], "network_id", "{name} {args:?}");
        let message = err["error"]["message"].as_str().unwrap_or_default();
        assert!(!message.contains("hostile"), "{name}: {message}");
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn get_device_rejects_a_missing_device_id_and_bad_types_before_any_request()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    for args in [
        object!({}),
        object!({"network_id": "network-0001"}),
        object!({"device_id": null}),
        object!({"device_id": 1.5}),
        object!({"device_id": ["device-0001"]}),
        object!({"device_id": "device-0001", "refresh": "yes"}),
        object!({"device_id": "device-0001", "detail": "full"}),
        object!({"device_id": "device-0001", "bogus": 1}),
    ] {
        let result = h.call("get_device", args.clone()).await?;
        assert_eq!(result.is_error, Some(true), "{args:?}");
        let text = result.content[0].as_text().expect("text").text.clone();
        assert!(
            text.starts_with("failed to deserialize parameters"),
            "{text}"
        );
    }
    let result = h.call_without_arguments("get_device").await?;
    assert_eq!(result.is_error, Some(true), "device_id is required");
    // A bad network_id is a validation error against its own parameter.
    let err = h
        .call_err(
            "get_device",
            object!({"network_id": "../hostile-0001", "device_id": "device-0001"}),
        )
        .await?;
    assert_eq!(err["error"]["field"], "network_id");
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn an_unknown_device_is_not_found_without_leaking_the_path() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    authed_get(DEVICE_ROUTE)
        .respond_with(json_status(
            404,
            &json!({"meta": {"code": 404, "error": "error.not_found"}, "data": {}}),
        ))
        .expect(1)
        .mount(&h.mock)
        .await;

    let err = h
        .call_err(
            "get_device",
            object!({"network_id": "network-0001", "device_id": "device-0001"}),
        )
        .await?;

    assert_eq!(err["error"]["code"], "not_found");
    assert_eq!(err["error"]["upstream_status"], 404);
    assert_clean(&err["error"]);
    Ok(())
}

// ===================== list_blocked_devices =====================

#[tokio::test]
async fn list_blocked_devices_reads_the_blacklist() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/blacklist",
        &devices_fixture("blacklist"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "list_blocked_devices",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = devices_json("blacklist");
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["data"][0]["mac"], "aa:bb:cc:00:00:03");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(
        out.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>()),
        Some(vec![
            "data".to_owned(),
            "network_id".to_owned(),
            "server_time".to_owned()
        ]),
        "no detail or count outside list_devices"
    );
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/blacklist"]
    );
    Ok(())
}

#[tokio::test]
async fn list_blocked_devices_is_not_cached_and_an_empty_list_is_an_empty_list()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/blacklist",
        &devices_fixture("blacklist_empty"),
        2,
    )
    .await;
    for _ in 0..2 {
        let out = h
            .call_ok(
                "list_blocked_devices",
                object!({"network_id": "network-0001"}),
            )
            .await?;
        assert_eq!(out["data"], json!([]));
    }
    // The read has no refresh input.
    let result = h
        .call(
            "list_blocked_devices",
            object!({"network_id": "network-0001", "refresh": true}),
        )
        .await?;
    assert_eq!(result.is_error, Some(true));
    assert_eq!(h.targets().await.len(), 2, "the rejected call sent nothing");
    Ok(())
}

#[tokio::test]
async fn list_blocked_devices_without_a_network_id_uses_the_only_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get(
        "/2.2/networks/network-0001/blacklist",
        &devices_fixture("blacklist"),
        1,
    )
    .await;

    let out = h.call_ok("list_blocked_devices", object!({})).await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks",
            "GET /2.2/networks/network-0001/blacklist"
        ]
    );
    Ok(())
}

// ===================== get_transfer_stats =====================

#[tokio::test]
async fn get_transfer_stats_without_a_device_reads_the_network_wide_path() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/transfer",
        &devices_fixture("transfer_stats"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_transfer_stats",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = devices_json("transfer_stats");
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["data"]["total_download"], 1_073_741_824_u64);
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/transfer"]
    );
    Ok(())
}

#[tokio::test]
async fn get_transfer_stats_with_a_device_reads_the_device_path() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/devices/device-0001/transfer",
        &devices_fixture("transfer_stats_device"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_transfer_stats",
            object!({"network_id": "network-0001", "device_id": "device-0001"}),
        )
        .await?;

    let wire = devices_json("transfer_stats_device");
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/devices/device-0001/transfer"]
    );
    Ok(())
}

#[tokio::test]
async fn get_transfer_stats_takes_every_device_id_form() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    let forms = [
        "device-0001".to_owned(),
        "  device-0001  ".to_owned(),
        DEVICE_ROUTE.to_owned(),
        format!("{DEVICE_ROUTE}/"),
        format!("{origin}{DEVICE_ROUTE}"),
    ];
    h.mount_get(
        &format!("{DEVICE_ROUTE}/transfer"),
        &devices_fixture("transfer_stats_device"),
        u64::try_from(forms.len())?,
    )
    .await;
    // A MAC goes out as written, like any other device id.
    h.mount_get(
        "/2.2/networks/network-0001/devices/aa:bb:cc:00:00:01/transfer",
        &devices_fixture("transfer_stats_device"),
        1,
    )
    .await;

    for form in forms {
        h.call_ok(
            "get_transfer_stats",
            object!({"network_id": "network-0001", "device_id": form}),
        )
        .await?;
    }
    h.call_ok(
        "get_transfer_stats",
        object!({"network_id": "network-0001", "device_id": "aa:bb:cc:00:00:01"}),
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn an_omitted_or_null_device_id_means_network_wide_and_an_empty_one_is_rejected()
-> anyhow::Result<()> {
    // Omitted and null both read the network-wide path.
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/transfer",
        &devices_fixture("transfer_stats"),
        2,
    )
    .await;
    h.call_ok(
        "get_transfer_stats",
        object!({"network_id": "network-0001"}),
    )
    .await?;
    h.call_ok(
        "get_transfer_stats",
        object!({"network_id": "network-0001", "device_id": null}),
    )
    .await?;
    drop(h);

    // An empty or blank one is an error: rusteero would read it as absent and silently answer
    // network-wide, which is not what the caller asked for.
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    for blank in ["", "   "] {
        let err = h
            .call_err(
                "get_transfer_stats",
                object!({"network_id": "network-0001", "device_id": blank}),
            )
            .await?;
        assert_eq!(err["error"]["code"], "invalid_argument", "{blank:?}");
        assert_eq!(err["error"]["field"], "device_id", "{blank:?}");
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn get_transfer_stats_checks_a_device_path_against_the_network() -> anyhow::Result<()> {
    let other = "/2.2/networks/network-0002/devices/device-0001";

    let h = Harness::start().await?;
    h.expect_no_requests().await;
    let err = h
        .call_err(
            "get_transfer_stats",
            object!({"network_id": "network-0001", "device_id": other}),
        )
        .await?;
    assert_eq!(err["error"]["code"], "invalid_argument");
    assert_eq!(err["error"]["field"], "device_id");
    h.assert_no_requests().await;
    drop(h);

    // With a defaulted network the check follows the network list and precedes the read.
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    let err = h
        .call_err("get_transfer_stats", object!({"device_id": other}))
        .await?;
    assert_eq!(err["error"]["field"], "device_id");
    assert_eq!(h.targets().await, ["GET /2.2/networks"]);
    Ok(())
}

#[tokio::test]
async fn get_transfer_stats_without_a_network_id_uses_the_only_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get(
        "/2.2/networks/network-0001/transfer",
        &devices_fixture("transfer_stats"),
        1,
    )
    .await;

    let out = h.call_ok("get_transfer_stats", object!({})).await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks",
            "GET /2.2/networks/network-0001/transfer"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn get_transfer_stats_is_not_cached() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/transfer",
        &devices_fixture("transfer_stats"),
        2,
    )
    .await;
    for _ in 0..2 {
        h.call_ok(
            "get_transfer_stats",
            object!({"network_id": "network-0001"}),
        )
        .await?;
    }
    Ok(())
}

// ----- the 403 nuance -----

/// Mounts one 403 on the network-wide transfer path and returns the tool error.
async fn transfer_403(body: &Value) -> anyhow::Result<Value> {
    let h = Harness::start().await?;
    authed_get("/2.2/networks/network-0001/transfer")
        .respond_with(json_status(403, body))
        .expect(1)
        .mount(&h.mock)
        .await;
    let err = h
        .call_err(
            "get_transfer_stats",
            object!({"network_id": "network-0001"}),
        )
        .await?;
    Ok(err["error"].clone())
}

#[tokio::test]
async fn a_403_with_error_access_denied_is_access_denied() -> anyhow::Result<()> {
    let error = transfer_403(&json!({
        "meta": {"code": 403, "error": "error.access.denied"},
        "data": {"password": "hunter2"}
    }))
    .await?;

    assert_eq!(error["code"], "access_denied");
    assert_eq!(error["upstream_status"], 403);
    assert_eq!(error["upstream_code"], "error.access.denied");
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn a_plain_403_is_an_upstream_error_with_status_403() -> anyhow::Result<()> {
    let error = transfer_403(&json!({"meta": {"code": 403}, "data": {}})).await?;

    assert_eq!(error["code"], "upstream_error");
    assert_eq!(error["upstream_status"], 403);
    assert!(error.get("upstream_code").is_none());
    assert_eq!(error["message"], "The eero cloud API returned an error.");
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn a_403_with_a_subscription_code_is_premium_required() -> anyhow::Result<()> {
    let error = transfer_403(&json!({
        "meta": {"code": 403, "error": "error.premium.user_not_subscribed"},
        "data": {}
    }))
    .await?;

    assert_eq!(error["code"], "premium_required");
    assert_eq!(error["upstream_status"], 403);
    assert_eq!(error["upstream_code"], "error.premium.user_not_subscribed");
    assert_clean(&error);
    Ok(())
}

#[tokio::test]
async fn the_device_transfer_path_maps_a_403_the_same_way() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    authed_get("/2.2/networks/network-0001/devices/device-0001/transfer")
        .respond_with(json_status(
            403,
            &json!({"meta": {"code": 403, "error": "error.access.denied"}, "data": {}}),
        ))
        .expect(1)
        .mount(&h.mock)
        .await;

    let err = h
        .call_err(
            "get_transfer_stats",
            object!({"network_id": "network-0001", "device_id": "device-0001"}),
        )
        .await?;

    assert_eq!(err["error"]["code"], "access_denied");
    assert_eq!(err["error"]["upstream_status"], 403);
    assert_clean(&err["error"]);
    Ok(())
}

#[tokio::test]
async fn the_description_of_get_transfer_stats_states_the_403_nuance() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;
    let description = tool(&tools, "get_transfer_stats")
        .description
        .as_deref()
        .unwrap_or_default()
        .to_owned();
    for needle in [
        "403",
        "access_denied",
        "premium_required",
        "upstream_error",
        "not_found",
        "do not retry",
    ] {
        assert!(description.contains(needle), "{needle}: {description}");
    }
    Ok(())
}

#[tokio::test]
async fn the_description_of_list_devices_names_every_summary_field_and_the_count_caveat()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;
    let description = tool(&tools, "list_devices")
        .description
        .as_deref()
        .unwrap_or_default()
        .to_owned();
    for needle in [
        "model name",
        "prioritized",
        "first and last active",
        "detail to full",
        "count is absent",
    ] {
        assert!(description.contains(needle), "{needle}: {description}");
    }
    Ok(())
}

// ===================== several networks, every device tool =====================

#[tokio::test]
async fn several_networks_without_a_network_id_list_each_id_on_every_device_tool()
-> anyhow::Result<()> {
    for tool_name in DEVICE_TOOLS {
        let h = Harness::start().await?;
        authed_get("/2.2/networks")
            .respond_with(json_response(&two_networks()))
            .expect(1)
            .mount(&h.mock)
            .await;

        let args = if tool_name == "get_device" {
            object!({"device_id": "device-0001"})
        } else {
            object!({})
        };
        let err = h.call_err(tool_name, args).await?;

        assert_eq!(err["error"]["code"], "invalid_argument", "{tool_name}");
        assert_eq!(err["error"]["field"], "network_id", "{tool_name}");
        let message = err["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("network-0001 (Example-Network)")
                && message.contains("network-0002 (Second-Network)"),
            "{tool_name}: {message}"
        );
        assert_eq!(
            h.targets().await,
            ["GET /2.2/networks"],
            "{tool_name}: nothing else is read"
        );
    }
    Ok(())
}

// ===================== both credentials, no query, on every device read =====================

#[tokio::test]
async fn every_device_read_sends_both_credentials_and_no_query() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    for (route, name) in [
        (LIST_ROUTE, "devices"),
        (DEVICE_ROUTE, "device"),
        ("/2.2/networks/network-0001/blacklist", "blacklist"),
        ("/2.2/networks/network-0001/transfer", "transfer_stats"),
        (
            "/2.2/networks/network-0001/devices/device-0001/transfer",
            "transfer_stats_device",
        ),
    ] {
        // authed_get requires both credential headers and pins the query to exactly nothing.
        authed_get(route)
            .respond_with(json_response(&devices_fixture(name)))
            .expect(1)
            .mount(&h.mock)
            .await;
    }

    h.call_ok("list_devices", object!({"network_id": "network-0001"}))
        .await?;
    h.call_ok(
        "get_device",
        object!({"network_id": "network-0001", "device_id": "device-0001"}),
    )
    .await?;
    h.call_ok(
        "list_blocked_devices",
        object!({"network_id": "network-0001"}),
    )
    .await?;
    h.call_ok(
        "get_transfer_stats",
        object!({"network_id": "network-0001"}),
    )
    .await?;
    h.call_ok(
        "get_transfer_stats",
        object!({"network_id": "network-0001", "device_id": "device-0001"}),
    )
    .await?;

    let received = h.received().await;
    assert_eq!(received.len(), 5);
    for request in received {
        assert_eq!(request.url.query(), None, "{}", request.url);
        assert_eq!(request.method.as_str(), "GET");
    }
    Ok(())
}
