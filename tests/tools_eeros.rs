//! Pins the eeros-group tools (8 to 10): the listing and annotations, the exact GET path, both
//! credentials, the output shape (`data`, `network_id`, `server_time`), cache and refresh call
//! counts (`list_eeros` is cached; `get_eero` never is and has no `refresh`), default-network
//! resolution, every eero id form, and validation before any request.

mod common;

use common::{Harness, authed_get, fixture, fixture_json, json_response, json_status};
use rmcp::model::Tool;
use rmcp::object;
use serde_json::{Value, json};

const GROUP: &str = "eeros";

fn eeros_fixture(name: &str) -> String {
    fixture(GROUP, name)
}

fn eeros_json(name: &str) -> Value {
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
        "eero-0001",
        "/2.2/",
        "hunter2",
        "test-token",
    ] {
        assert!(!rendered.contains(leak), "{leak:?} leaked into {rendered}");
    }
}

const EERO_TOOLS: [&str; 3] = ["list_eeros", "get_eero", "list_eero_connections"];

/// The two tools that take a required `eero_id`, with the path suffix of their read and the
/// fixture they are served from.
const NODE_TOOLS: [(&str, &str, &str); 2] = [
    ("get_eero", "", "eero"),
    ("list_eero_connections", "/connections", "eero_connections"),
];

// ===================== the listed tools =====================

#[tokio::test]
async fn the_three_eero_tools_are_listed_read_only_with_titles_and_output_schemas()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for name in EERO_TOOLS {
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
    }
    Ok(())
}

#[tokio::test]
async fn the_eero_tools_publish_their_documented_inputs() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    // list_eeros is the cached one: network_id and refresh, nothing required.
    let list = tool(&tools, "list_eeros");
    assert!(has_property(list, "network_id"));
    assert!(has_property(list, "refresh"));
    assert!(!has_property(list, "eero_id"));
    assert!(list.input_schema.get("required").is_none());

    // get_eero and list_eero_connections: a required eero_id, an optional network_id, no refresh
    // (get_eero is never cached; the connections read is not one of the eight cached getters).
    for name in ["get_eero", "list_eero_connections"] {
        let listed = tool(&tools, name);
        assert!(has_property(listed, "eero_id"), "{name}");
        assert!(has_property(listed, "network_id"), "{name}");
        assert!(!has_property(listed, "refresh"), "{name}");
        assert_eq!(
            listed.input_schema["required"],
            json!(["eero_id"]),
            "{name}"
        );
        // Integers are accepted but the published type is string.
        for id in ["eero_id", "network_id"] {
            assert_eq!(
                listed.input_schema["properties"][id]["type"], "string",
                "{name}.{id}"
            );
        }
    }
    Ok(())
}

// ===================== list_eeros =====================

#[tokio::test]
async fn list_eeros_returns_the_node_list_and_the_queried_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/eeros",
        &eeros_fixture("eeros"),
        1,
    )
    .await;

    let out = h
        .call_ok("list_eeros", object!({"network_id": "network-0001"}))
        .await?;

    let wire = eeros_json("eeros");
    assert_eq!(
        out["data"], wire["data"],
        "no deny-listed key in this fixture"
    );
    assert_eq!(out["data"][0]["url"], "/2.2/eeros/eero-0001");
    assert_eq!(out["data"][1]["location"], "Bedroom");
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
        "only the documented members; the rest of the envelope meta is dropped"
    );
    assert_eq!(h.targets().await, ["GET /2.2/networks/network-0001/eeros"]);
    Ok(())
}

#[tokio::test]
async fn list_eeros_serves_a_repeat_from_cache_and_refresh_bypasses_it() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // The first call and the refresh; the repeats in between are cache hits.
    h.mount_get(
        "/2.2/networks/network-0001/eeros",
        &eeros_fixture("eeros"),
        2,
    )
    .await;

    for args in [
        object!({"network_id": "network-0001"}),
        object!({"network_id": "network-0001"}),
        object!({"network_id": "network-0001", "refresh": false}),
        object!({"network_id": "network-0001", "refresh": true}),
        object!({"network_id": "network-0001"}),
    ] {
        h.call_ok("list_eeros", args).await?;
    }
    assert_eq!(h.targets().await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn list_eeros_without_a_network_id_uses_the_only_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get(
        "/2.2/networks/network-0001/eeros",
        &eeros_fixture("eeros"),
        1,
    )
    .await;

    let out = h.call_ok("list_eeros", object!({})).await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks", "GET /2.2/networks/network-0001/eeros"]
    );
    Ok(())
}

#[tokio::test]
async fn list_eeros_accepts_every_network_id_form() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    let forms = [
        json!("network-0001"),
        json!("  network-0001  "),
        json!("/2.2/networks/network-0001"),
        json!("/2.2/networks/network-0001/"),
        json!(format!("{origin}/2.2/networks/network-0001")),
    ];
    h.mount_get(
        "/2.2/networks/network-0001/eeros",
        &eeros_fixture("eeros"),
        u64::try_from(forms.len())?,
    )
    .await;

    for form in forms {
        let out = h
            .call_ok(
                "list_eeros",
                object!({"network_id": form.clone(), "refresh": true}),
            )
            .await?;
        assert_eq!(out["network_id"], "network-0001", "{form}");
    }
    Ok(())
}

#[tokio::test]
async fn list_eeros_rejects_a_bad_network_id_and_unknown_fields_before_any_request()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in ["", "   ", "../hostile-0001", "/2.2/eeros/eero-0001"] {
        let err = h
            .call_err("list_eeros", object!({"network_id": bad}))
            .await?;
        assert_eq!(err["error"]["code"], "invalid_argument", "{bad:?}");
        assert_eq!(err["error"]["field"], "network_id", "{bad:?}");
        let message = err["error"]["message"].as_str().unwrap_or_default();
        assert!(!message.contains("hostile"), "{message}");
    }
    for args in [
        object!({"eero_id": "eero-0001"}),
        object!({"refresh": "yes"}),
        object!({"bogus": 1}),
    ] {
        let result = h.call("list_eeros", args.clone()).await?;
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

// ===================== get_eero =====================

#[tokio::test]
async fn get_eero_reads_the_eero_path_and_echoes_the_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/eeros/eero-0001", &eeros_fixture("eero"), 1)
        .await;

    let out = h
        .call_ok(
            "get_eero",
            object!({"network_id": "network-0001", "eero_id": "eero-0001"}),
        )
        .await?;

    let wire = eeros_json("eero");
    assert_eq!(
        out["data"], wire["data"],
        "no deny-listed key in this fixture"
    );
    assert_eq!(out["data"]["location"], "Living Room");
    assert_eq!(out["data"]["reboots"]["last_week"], 1);
    assert_eq!(
        out["network_id"], "network-0001",
        "the network context, not part of the request"
    );
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert!(out.get("window").is_none());
    assert_eq!(h.targets().await, ["GET /2.2/eeros/eero-0001"]);
    Ok(())
}

#[tokio::test]
async fn get_eero_is_never_cached_and_has_no_refresh() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    // A refresh flag is an unknown field for this tool: rejected before any request.
    let result = h
        .call(
            "get_eero",
            object!({"network_id": "network-0001", "eero_id": "eero-0001", "refresh": true}),
        )
        .await?;
    assert_eq!(result.is_error, Some(true));
    let text = result.content[0].as_text().expect("text").text.clone();
    assert!(
        text.starts_with("failed to deserialize parameters"),
        "{text}"
    );
    h.assert_no_requests().await;

    // And every call asks eero: three calls, three requests. A fresh harness, because the
    // catch-all above fails its mock for any request.
    let h = Harness::start().await?;
    h.mount_get("/2.2/eeros/eero-0001", &eeros_fixture("eero"), 3)
        .await;
    for _ in 0..3 {
        h.call_ok(
            "get_eero",
            object!({"network_id": "network-0001", "eero_id": "eero-0001"}),
        )
        .await?;
    }
    assert_eq!(h.targets().await.len(), 3);
    Ok(())
}

#[tokio::test]
async fn get_eero_after_list_eeros_still_reads_the_eero_path() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/eeros",
        &eeros_fixture("eeros"),
        1,
    )
    .await;
    h.mount_get("/2.2/eeros/eero-0001", &eeros_fixture("eero"), 1)
        .await;

    h.call_ok("list_eeros", object!({"network_id": "network-0001"}))
        .await?;
    let out = h
        .call_ok(
            "get_eero",
            object!({"network_id": "network-0001", "eero_id": "eero-0001"}),
        )
        .await?;

    assert_eq!(out["data"]["led_brightness"], 100, "the full node object");
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks/network-0001/eeros",
            "GET /2.2/eeros/eero-0001"
        ]
    );
    Ok(())
}

// ===================== list_eero_connections =====================

#[tokio::test]
async fn list_eero_connections_reads_the_connections_path() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/eeros/eero-0001/connections",
        &eeros_fixture("eero_connections"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "list_eero_connections",
            object!({"network_id": "network-0001", "eero_id": "eero-0001"}),
        )
        .await?;

    let wire = eeros_json("eero_connections");
    assert_eq!(
        out["data"], wire["data"],
        "no deny-listed key in this fixture"
    );
    assert_eq!(
        out["data"]["wireless_devices"][0]["mac"],
        "aa:bb:cc:00:00:01"
    );
    assert_eq!(
        out["data"]["wireless_devices"][1]["nickname"],
        Value::Null,
        "null values stay visible"
    );
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(h.targets().await, ["GET /2.2/eeros/eero-0001/connections"]);
    Ok(())
}

#[tokio::test]
async fn list_eero_connections_is_not_cached_and_has_no_refresh() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/eeros/eero-0001/connections",
        &eeros_fixture("eero_connections"),
        2,
    )
    .await;
    for _ in 0..2 {
        h.call_ok(
            "list_eero_connections",
            object!({"network_id": "network-0001", "eero_id": "eero-0001"}),
        )
        .await?;
    }
    let result = h
        .call(
            "list_eero_connections",
            object!({"network_id": "network-0001", "eero_id": "eero-0001", "refresh": true}),
        )
        .await?;
    assert_eq!(result.is_error, Some(true), "refresh is an unknown field");
    assert_eq!(h.targets().await.len(), 2, "the rejected call sent nothing");
    Ok(())
}

#[tokio::test]
async fn list_eero_connections_follows_the_link_of_a_listed_node() -> anyhow::Result<()> {
    // After list_eeros, rusteero prefers the node's own published connections link; the fixture's
    // link is the same path, so the request is unchanged.
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/eeros",
        &eeros_fixture("eeros"),
        1,
    )
    .await;
    h.mount_get(
        "/2.2/eeros/eero-0002/connections",
        &eeros_fixture("eero_connections"),
        1,
    )
    .await;

    h.call_ok("list_eeros", object!({"network_id": "network-0001"}))
        .await?;
    h.call_ok(
        "list_eero_connections",
        object!({"network_id": "network-0001", "eero_id": "eero-0002"}),
    )
    .await?;
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks/network-0001/eeros",
            "GET /2.2/eeros/eero-0002/connections"
        ]
    );
    Ok(())
}

// ===================== eero id forms and default network, both node tools =====================

#[tokio::test]
async fn every_eero_id_form_reaches_the_same_get_on_both_node_tools() -> anyhow::Result<()> {
    for (tool_name, suffix, name) in NODE_TOOLS {
        let h = Harness::start().await?;
        let origin = h.origin();
        let forms = [
            json!("eero-0001"),
            json!("  eero-0001  "),
            json!("/2.2/eeros/eero-0001"),
            json!("/2.2/eeros/eero-0001/"),
            json!("/2.3/eeros/eero-0001"),
            json!(format!("{origin}/2.2/eeros/eero-0001")),
            json!(format!("{origin}/2.2/eeros/eero-0001/")),
        ];
        h.mount_get(
            &format!("/2.2/eeros/eero-0001{suffix}"),
            &eeros_fixture(name),
            u64::try_from(forms.len())?,
        )
        .await;

        for form in forms {
            // Neither read is cached, so every form puts one request on the wire.
            let out = h
                .call_ok(
                    tool_name,
                    object!({"network_id": "network-0001", "eero_id": form.clone()}),
                )
                .await?;
            assert_eq!(out["network_id"], "network-0001", "{tool_name} {form}");
        }
        assert!(
            h.targets()
                .await
                .iter()
                .all(|target| *target == format!("GET /2.2/eeros/eero-0001{suffix}")),
            "{tool_name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_integer_eero_id_is_accepted_and_rendered_in_decimal() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/eeros/12345", &eeros_fixture("eero"), 1)
        .await;
    h.call_ok(
        "get_eero",
        object!({"network_id": "network-0001", "eero_id": 12345}),
    )
    .await?;
    assert_eq!(h.targets().await, ["GET /2.2/eeros/12345"]);
    Ok(())
}

#[tokio::test]
async fn an_omitted_network_id_uses_the_only_network_on_both_node_tools() -> anyhow::Result<()> {
    for (tool_name, suffix, name) in NODE_TOOLS {
        let h = Harness::start().await?;
        h.mount_single_network(1).await;
        let route = format!("/2.2/eeros/eero-0001{suffix}");
        h.mount_get(&route, &eeros_fixture(name), 1).await;

        let out = h
            .call_ok(tool_name, object!({"eero_id": "eero-0001"}))
            .await?;

        assert_eq!(out["network_id"], "network-0001", "{tool_name}");
        assert_eq!(
            h.targets().await,
            ["GET /2.2/networks".to_owned(), format!("GET {route}")],
            "{tool_name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn several_networks_without_a_network_id_list_each_id_on_every_eero_tool()
-> anyhow::Result<()> {
    let two_networks = json!({
        "meta": {"code": 200, "server_time": "2026-01-01T00:00:15Z"},
        "data": [
            {"url": "/2.2/networks/network-0001", "name": "Example-Network"},
            {"url": "/2.2/networks/network-0002", "name": "Second-Network"}
        ]
    });
    for tool_name in EERO_TOOLS {
        let h = Harness::start().await?;
        authed_get("/2.2/networks")
            .respond_with(json_response(&two_networks.to_string()))
            .expect(1)
            .mount(&h.mock)
            .await;

        let args = if tool_name == "list_eeros" {
            object!({})
        } else {
            object!({"eero_id": "eero-0001"})
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

// ===================== validation before any request =====================

#[tokio::test]
async fn invalid_eero_ids_fail_before_any_request_on_both_node_tools() -> anyhow::Result<()> {
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
        "/2.2/networks/network-0001",
        "/2.2/eeros/eero-0001/reboot",
        "/2.2/eeros/../hostile-0001",
        "/2.2/eeros/",
        "https://api-user.e2ro.com/2.2/eeros/eero-0001",
        "http://other.test:1234/2.2/eeros/eero-0001",
    ];
    for (name, _, _) in NODE_TOOLS {
        for bad in bad_ids {
            let err = h
                .call_err(
                    name,
                    object!({"network_id": "network-0001", "eero_id": bad}),
                )
                .await?;
            assert_eq!(err["error"]["code"], "invalid_argument", "{name} {bad:?}");
            assert_eq!(err["error"]["field"], "eero_id", "{name} {bad:?}");
            let message = err["error"]["message"].as_str().unwrap_or_default();
            assert!(!message.is_empty());
            for echoed in ["hostile", "other.test", "e2ro", "reboot", "network-0001"] {
                assert!(!message.contains(echoed), "{name} {bad:?}: {message}");
            }
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_bad_network_id_is_reported_against_network_id_on_both_node_tools() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    for (name, _, _) in NODE_TOOLS {
        for bad in ["", "../hostile-0001", "/2.2/eeros/eero-0001"] {
            let err = h
                .call_err(name, object!({"network_id": bad, "eero_id": "eero-0001"}))
                .await?;
            assert_eq!(err["error"]["code"], "invalid_argument", "{name} {bad:?}");
            assert_eq!(err["error"]["field"], "network_id", "{name} {bad:?}");
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_missing_or_null_eero_id_and_unknown_fields_are_rejected_by_the_schema()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    for (name, _, _) in NODE_TOOLS {
        for args in [
            object!({}),
            object!({"network_id": "network-0001"}),
            object!({"eero_id": null}),
            object!({"eero_id": 1.5}),
            object!({"eero_id": true}),
            object!({"eero_id": "eero-0001", "bogus": 1}),
        ] {
            let result = h.call(name, args.clone()).await?;
            assert_eq!(result.is_error, Some(true), "{name} {args:?}");
            let text = result.content[0].as_text().expect("text").text.clone();
            assert!(
                text.starts_with("failed to deserialize parameters"),
                "{name}: {text}"
            );
        }
    }
    let result = h.call_without_arguments("get_eero").await?;
    assert_eq!(result.is_error, Some(true), "eero_id is required");
    h.assert_no_requests().await;
    Ok(())
}

// ===================== errors =====================

#[tokio::test]
async fn an_unknown_eero_is_not_found_without_leaking_the_path() -> anyhow::Result<()> {
    for (tool_name, suffix, _) in NODE_TOOLS {
        let h = Harness::start().await?;
        authed_get(&format!("/2.2/eeros/eero-0001{suffix}"))
            .respond_with(json_status(
                404,
                &json!({"meta": {"code": 404, "error": "error.not_found"}, "data": {}}),
            ))
            .expect(1)
            .mount(&h.mock)
            .await;

        let err = h
            .call_err(
                tool_name,
                object!({"network_id": "network-0001", "eero_id": "eero-0001"}),
            )
            .await?;

        assert_eq!(err["error"]["code"], "not_found", "{tool_name}");
        assert_eq!(err["error"]["upstream_status"], 404, "{tool_name}");
        assert_clean(&err["error"]);
    }
    Ok(())
}

#[tokio::test]
async fn an_offline_eero_is_feature_unavailable_on_the_node_tools() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    authed_get("/2.2/eeros/eero-0001/connections")
        .respond_with(json_status(
            404,
            &json!({"meta": {"code": 404, "error": "error.eero.offline"}, "data": {}}),
        ))
        .expect(1)
        .mount(&h.mock)
        .await;

    let err = h
        .call_err(
            "list_eero_connections",
            object!({"network_id": "network-0001", "eero_id": "eero-0001"}),
        )
        .await?;

    assert_eq!(err["error"]["code"], "feature_unavailable");
    assert_eq!(err["error"]["upstream_code"], "error.eero.offline");
    assert_clean(&err["error"]);
    Ok(())
}

// ===================== both credentials, no query, on every eero read =====================

#[tokio::test]
async fn every_eero_read_sends_both_credentials_and_no_query() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    for (route, name) in [
        ("/2.2/networks/network-0001/eeros", "eeros"),
        ("/2.2/eeros/eero-0001", "eero"),
        ("/2.2/eeros/eero-0001/connections", "eero_connections"),
    ] {
        // authed_get requires both credential headers and pins the query to exactly nothing.
        authed_get(route)
            .respond_with(json_response(&eeros_fixture(name)))
            .expect(1)
            .mount(&h.mock)
            .await;
    }

    h.call_ok("list_eeros", object!({"network_id": "network-0001"}))
        .await?;
    for (tool_name, _, _) in NODE_TOOLS {
        h.call_ok(
            tool_name,
            object!({"network_id": "network-0001", "eero_id": "eero-0001"}),
        )
        .await?;
    }
    let received = h.received().await;
    assert_eq!(received.len(), 3);
    for request in received {
        assert_eq!(request.url.query(), None, "{}", request.url);
        assert_eq!(request.method.as_str(), "GET");
    }
    Ok(())
}
