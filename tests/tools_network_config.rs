//! Pins the network-configuration tools (26 to 32): the listing and annotations, the exact GET path
//! (no query) and both credentials, the output shape (`data`, `network_id`, `server_time`),
//! redaction of subnet and backup-internet secrets, that none of the seven is cached, default
//! network resolution, every `network_id` form, eero Plus gating (`premium_required`), and
//! validation before any request.

mod common;

use common::{Harness, authed_get, fixture, fixture_json, json_response, json_status};
use rmcp::model::Tool;
use rmcp::object;
use serde_json::{Value, json};

const REDACTED: &str = "[REDACTED]";
const GROUP: &str = "network_config";

fn config_fixture(name: &str) -> String {
    fixture(GROUP, name)
}

fn config_json(name: &str) -> Value {
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

/// Every tool of the group with the path suffix under the network and its fixture.
const CONFIG_READS: [(&str, &str, &str); 7] = [
    ("list_port_forwards", "/forwards", "forwards"),
    ("list_dhcp_reservations", "/reservations", "reservations"),
    ("get_subnets", "/subnets_config", "subnets"),
    ("get_wpa3_settings", "/wpa3_per_band", "wpa3"),
    ("get_fast_transition", "/fast_transition", "fast_transition"),
    (
        "get_content_filter",
        "/dns_policies/advanced_content_filter",
        "content_filter",
    ),
    ("get_backup_internet", "/backupinternet", "backup_internet"),
];

/// The two tools that need eero Plus.
const PLUS_TOOLS: [&str; 2] = ["get_content_filter", "get_backup_internet"];

fn route(network: &str, suffix: &str) -> String {
    format!("/2.2/networks/{network}{suffix}")
}

// ===================== the listed tools =====================

#[tokio::test]
async fn the_seven_config_tools_are_listed_read_only_with_titles_and_output_schemas()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for (name, _, _) in CONFIG_READS {
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
            listed.input_schema.get("type"),
            Some(&json!("object")),
            "{name}"
        );
        assert_eq!(
            listed.input_schema.get("additionalProperties"),
            Some(&json!(false)),
            "{name} rejects unknown fields"
        );
    }
    Ok(())
}

#[tokio::test]
async fn the_config_tools_take_only_an_optional_network_id_and_no_refresh() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for (name, _, _) in CONFIG_READS {
        let listed = tool(&tools, name);
        assert!(has_property(listed, "network_id"), "{name}");
        // Integers are accepted but the published type is string.
        assert_eq!(
            listed.input_schema["properties"]["network_id"]["type"], "string",
            "{name}"
        );
        assert!(listed.input_schema.get("required").is_none(), "{name}");
        // None of the seven is backed by one of rusteero's cached getters.
        assert!(!has_property(listed, "refresh"), "{name}");
        let properties = listed.input_schema["properties"]
            .as_object()
            .map_or(0, serde_json::Map::len);
        assert_eq!(properties, 1, "{name}: network_id only");
    }
    Ok(())
}

#[tokio::test]
async fn only_the_two_plus_tools_describe_the_eero_plus_gating() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for (name, _, _) in CONFIG_READS {
        let description = tool(&tools, name)
            .description
            .as_deref()
            .unwrap_or_default();
        if PLUS_TOOLS.contains(&name) {
            assert!(description.contains("eero Plus"), "{name}: {description}");
            assert!(
                description.contains("premium_required"),
                "{name}: {description}"
            );
        } else {
            assert!(!description.contains("eero Plus"), "{name}: {description}");
        }
    }
    Ok(())
}

// ===================== list_port_forwards =====================

#[tokio::test]
async fn list_port_forwards_reads_forwards_and_echoes_the_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        &route("network-0001", "/forwards"),
        &config_fixture("forwards"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "list_port_forwards",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = config_json("forwards");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"], "no deny-listed key here");
    assert_eq!(out["data"][0]["gateway_port"], 8080);
    assert_eq!(out["data"][0]["ip"], "192.0.2.11");
    assert_eq!(
        out.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>()),
        Some(vec![
            "data".to_owned(),
            "network_id".to_owned(),
            "server_time".to_owned()
        ]),
        "only the documented members; the rest of the meta is dropped"
    );
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/forwards"]
    );
    Ok(())
}

// ===================== list_dhcp_reservations =====================

#[tokio::test]
async fn list_dhcp_reservations_reads_reservations() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        &route("network-0001", "/reservations"),
        &config_fixture("reservations"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "list_dhcp_reservations",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = config_json("reservations");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["data"][0]["mac"], "aa:bb:cc:00:00:01");
    assert_eq!(out["data"][1]["ip"], "192.0.2.12");
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/reservations"]
    );
    Ok(())
}

// ===================== get_subnets =====================

#[tokio::test]
async fn get_subnets_reads_subnets_config_and_redacts_the_subnet_passwords() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        &route("network-0001", "/subnets_config"),
        &config_fixture("subnets"),
        1,
    )
    .await;

    let out = h
        .call_ok("get_subnets", object!({"network_id": "network-0001"}))
        .await?;

    let wire = config_json("subnets");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    // Only the non-empty password (inside an array of objects) is replaced; everything else is
    // exactly what eero sent.
    let mut expected = wire["data"].clone();
    expected["subnets"][0]["password"] = json!(REDACTED);
    assert_eq!(out["data"], expected);
    let guest = &out["data"]["subnets"][0];
    assert_eq!(guest["password"], REDACTED);
    assert_eq!(guest["name"], "Example-Network Guest");
    assert_eq!(guest["dedicated_subnet"]["subnet_ip"], "198.51.100.0");
    // An empty password and a null passphrase stay visible: "no password set" is information.
    let iot = &out["data"]["subnets"][1];
    assert_eq!(iot["password"], "");
    assert_eq!(iot["passphrase"], Value::Null);
    assert!(!out.to_string().contains("subnetpass000"), "secret leaked");
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/subnets_config"]
    );
    Ok(())
}

// ===================== get_wpa3_settings =====================

#[tokio::test]
async fn get_wpa3_settings_reads_the_per_band_mode() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        &route("network-0001", "/wpa3_per_band"),
        &config_fixture("wpa3"),
        1,
    )
    .await;

    let out = h
        .call_ok("get_wpa3_settings", object!({"network_id": "network-0001"}))
        .await?;

    let wire = config_json("wpa3");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["data"]["band_2_4_ghz"], "WPA2_WPA3");
    assert_eq!(out["data"]["band_6_ghz"], "WPA3");
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/wpa3_per_band"]
    );
    Ok(())
}

// ===================== get_fast_transition =====================

#[tokio::test]
async fn get_fast_transition_reads_the_roaming_setting() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        &route("network-0001", "/fast_transition"),
        &config_fixture("fast_transition"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_fast_transition",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = config_json("fast_transition");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["data"]["fast_transition"], true);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/fast_transition"]
    );
    Ok(())
}

// ===================== get_content_filter (eero Plus) =====================

#[tokio::test]
async fn get_content_filter_reads_the_allow_and_block_lists() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        &route("network-0001", "/dns_policies/advanced_content_filter"),
        &config_fixture("content_filter"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_content_filter",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = config_json("content_filter");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(
        out["data"]["allowed_list"][0]["domain_name"],
        "homework.example.com"
    );
    // An entry is network-wide only when applied_to_network is true; otherwise profile_list names
    // the profiles it covers.
    assert_eq!(out["data"]["blocked_list"][0]["applied_to_network"], true);
    assert_eq!(out["data"]["blocked_list"][1]["applied_to_network"], false);
    assert_eq!(
        out["data"]["blocked_list"][1]["profile_list"],
        json!([{
            "profile_name": "Kids",
            "profile_url": "/2.2/networks/network-0001/profiles/profile-0001"
        }])
    );
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/dns_policies/advanced_content_filter"]
    );
    Ok(())
}

// ===================== get_backup_internet (eero Plus) =====================

#[tokio::test]
async fn get_backup_internet_reads_the_configuration() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        &route("network-0001", "/backupinternet"),
        &config_fixture("backup_internet"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_backup_internet",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = config_json("backup_internet");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["data"]["backup_internet_enabled"], true);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/backupinternet"]
    );
    Ok(())
}

#[tokio::test]
async fn get_backup_internet_redacts_secret_keys_if_present() -> anyhow::Result<()> {
    // eero's observed response carries only backup_internet_enabled. This body is synthetic: it
    // adds deny-listed keys so the redaction pin does not depend on the shape of the real payload.
    let h = Harness::start().await?;
    let body = json!({
        "meta": {"code": 200, "server_time": "2026-01-01T00:01:22Z"},
        "data": {
            "backup_internet_enabled": true,
            "backup_connection": {
                "type": "cellular",
                "status": "standby",
                "ssid": "Example-Backup",
                "password": "backuppass000",
                "pppoe_credentials": {"username": "user@example.com", "secret": "pppoepass000"},
                "pre_shared_key": ""
            }
        }
    })
    .to_string();
    authed_get(&route("network-0001", "/backupinternet"))
        .respond_with(json_response(&body))
        .expect(1)
        .mount(&h.mock)
        .await;

    let out = h
        .call_ok(
            "get_backup_internet",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    assert_eq!(out["data"]["backup_internet_enabled"], true);
    let connection = &out["data"]["backup_connection"];
    assert_eq!(connection["password"], REDACTED);
    // A non-empty object under a deny-listed key is replaced whole.
    assert_eq!(connection["pppoe_credentials"], REDACTED);
    assert_eq!(
        connection["ssid"], "Example-Backup",
        "an SSID is not a secret"
    );
    assert_eq!(connection["status"], "standby");
    assert_eq!(
        connection["pre_shared_key"], "",
        "an empty secret stays visible"
    );
    let rendered = out.to_string();
    for secret in ["backuppass000", "pppoepass000", "user@example.com"] {
        assert!(!rendered.contains(secret), "{secret} leaked");
    }
    Ok(())
}

// ===================== eero Plus gating =====================

#[tokio::test]
async fn the_plus_tools_without_eero_plus_are_premium_required() -> anyhow::Result<()> {
    for (name, suffix, _) in CONFIG_READS {
        if !PLUS_TOOLS.contains(&name) {
            continue;
        }
        for status in [403, 404] {
            let h = Harness::start().await?;
            authed_get(&route("network-0001", suffix))
                .respond_with(json_status(
                    status,
                    &json!({
                        "meta": {"code": status, "error": "error.premium.user_not_subscribed"},
                        "data": {"password": "hunter2"}
                    }),
                ))
                .expect(1)
                .mount(&h.mock)
                .await;

            let err = h
                .call_err(name, object!({"network_id": "network-0001"}))
                .await?;

            assert_eq!(
                err["error"]["code"], "premium_required",
                "{name} status {status}"
            );
            assert_eq!(err["error"]["upstream_status"], status, "{name}");
            assert_eq!(
                err["error"]["upstream_code"], "error.premium.user_not_subscribed",
                "{name}"
            );
            let message = err["error"]["message"].as_str().unwrap_or_default();
            assert!(message.contains("eero Plus"), "{name}: {message}");
            let rendered = err.to_string();
            for leak in ["network-0001", "/2.2/", "hunter2", suffix] {
                assert!(
                    !rendered.contains(leak),
                    "{name}: {leak} leaked: {rendered}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_2xx_on_a_plus_tool_is_a_success_whatever_its_meta_carries() -> anyhow::Result<()> {
    // rusteero classifies meta.error only on error statuses.
    let h = Harness::start().await?;
    authed_get(&route("network-0001", "/backupinternet"))
        .respond_with(json_status(
            200,
            &json!({
                "meta": {"code": 200, "error": "error.premium.user_not_subscribed"},
                "data": {"backup_internet_enabled": false}
            }),
        ))
        .expect(1)
        .mount(&h.mock)
        .await;

    let out = h
        .call_ok(
            "get_backup_internet",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    assert_eq!(out["data"], json!({"backup_internet_enabled": false}));
    Ok(())
}

#[tokio::test]
async fn an_unsupported_feature_is_not_found_without_echoing_the_path() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    authed_get(&route("network-0001", "/subnets_config"))
        .respond_with(json_status(
            404,
            &json!({"meta": {"code": 404, "error": "error.resource.not_found"}, "data": {}}),
        ))
        .expect(1)
        .mount(&h.mock)
        .await;

    let err = h
        .call_err("get_subnets", object!({"network_id": "network-0001"}))
        .await?;

    assert_eq!(err["error"]["code"], "not_found");
    assert_eq!(err["error"]["upstream_status"], 404);
    let rendered = err.to_string();
    for leak in ["network-0001", "subnets_config", "/2.2/"] {
        assert!(!rendered.contains(leak), "{leak} leaked: {rendered}");
    }
    Ok(())
}

// ===================== none of the seven is cached =====================

#[tokio::test]
async fn none_of_the_config_tools_is_cached() -> anyhow::Result<()> {
    for (name, suffix, fixture_name) in CONFIG_READS {
        let h = Harness::start().await?;
        h.mount_get(
            &route("network-0001", suffix),
            &config_fixture(fixture_name),
            2,
        )
        .await;

        for _ in 0..2 {
            h.call_ok(name, object!({"network_id": "network-0001"}))
                .await?;
        }
        assert_eq!(h.targets().await.len(), 2, "{name}: every call is live");
    }
    Ok(())
}

// ===================== both credentials, no query, on every tool =====================

#[tokio::test]
async fn every_config_read_sends_both_credentials_and_no_query() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // authed_get requires both credential headers and pins the query to exactly nothing.
    for (_, suffix, fixture_name) in CONFIG_READS {
        authed_get(&route("network-0001", suffix))
            .respond_with(json_response(&config_fixture(fixture_name)))
            .expect(1)
            .mount(&h.mock)
            .await;
    }

    for (name, _, _) in CONFIG_READS {
        h.call_ok(name, object!({"network_id": "network-0001"}))
            .await?;
    }
    let received = h.received().await;
    assert_eq!(received.len(), CONFIG_READS.len());
    for request in received {
        assert_eq!(request.url.query(), None, "{}", request.url);
        assert_eq!(request.method.as_str(), "GET");
    }
    Ok(())
}

// ===================== network_id forms and default-network resolution =====================

#[tokio::test]
async fn every_network_id_form_reaches_the_same_get_on_every_config_tool() -> anyhow::Result<()> {
    for (name, suffix, fixture_name) in CONFIG_READS {
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
            &route("network-0001", suffix),
            &config_fixture(fixture_name),
            u64::try_from(forms.len())?,
        )
        .await;

        for form in forms {
            let out = h
                .call_ok(name, object!({"network_id": form.clone()}))
                .await?;
            assert_eq!(out["network_id"], "network-0001", "{name} {form}");
        }
        assert!(
            h.targets()
                .await
                .iter()
                .all(|target| *target == format!("GET {}", route("network-0001", suffix))),
            "{name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_integer_network_id_is_accepted_and_rendered_in_decimal() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        &route("12345", "/fast_transition"),
        &config_fixture("fast_transition"),
        1,
    )
    .await;

    let out = h
        .call_ok("get_fast_transition", object!({"network_id": 12345}))
        .await?;

    assert_eq!(out["network_id"], "12345");
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/12345/fast_transition"]
    );
    Ok(())
}

#[tokio::test]
async fn an_omitted_network_id_uses_the_only_network_on_every_config_tool() -> anyhow::Result<()> {
    for (name, suffix, fixture_name) in CONFIG_READS {
        let h = Harness::start().await?;
        h.mount_single_network(1).await;
        let read_route = route("network-0001", suffix);
        h.mount_get(&read_route, &config_fixture(fixture_name), 1)
            .await;

        let out = h.call_ok(name, object!({})).await?;

        assert_eq!(out["network_id"], "network-0001", "{name}");
        assert_eq!(
            h.targets().await,
            ["GET /2.2/networks".to_owned(), format!("GET {read_route}")],
            "{name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn several_networks_without_a_network_id_list_each_id_and_name() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let two = json!({
        "meta": {"code": 200, "server_time": "2026-01-01T00:00:15Z"},
        "data": [
            {"url": "/2.2/networks/network-0001", "name": "Example-Network"},
            {"url": "/2.2/networks/network-0002", "name": "Second-Network"}
        ]
    });
    authed_get("/2.2/networks")
        .respond_with(json_response(&two.to_string()))
        .expect(1)
        .mount(&h.mock)
        .await;

    let err = h.call_err("list_port_forwards", object!({})).await?;

    assert_eq!(err["error"]["code"], "invalid_argument");
    assert_eq!(err["error"]["field"], "network_id");
    let message = err["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("network-0001 (Example-Network)"),
        "{message}"
    );
    assert!(
        message.contains("network-0002 (Second-Network)"),
        "{message}"
    );
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks"],
        "nothing is read for a network chosen by the server"
    );
    Ok(())
}

// ===================== validation before any request =====================

#[tokio::test]
async fn invalid_network_ids_fail_before_any_request_on_every_config_tool() -> anyhow::Result<()> {
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
        "/2.2/eeros/eero-0001",
        "/2.2/networks/network-0001/devices",
        "https://api-user.e2ro.com/2.2/networks/network-0001",
        "http://other.test:1234/2.2/networks/network-0001",
    ];
    for (name, _, _) in CONFIG_READS {
        for bad in bad_ids {
            let err = h.call_err(name, object!({"network_id": bad})).await?;
            assert_eq!(err["error"]["code"], "invalid_argument", "{name} {bad:?}");
            assert_eq!(err["error"]["field"], "network_id", "{name} {bad:?}");
            let message = err["error"]["message"].as_str().unwrap_or_default();
            assert!(!message.is_empty());
            for echoed in ["hostile", "other.test", "e2ro", "eero-0001", "devices"] {
                assert!(!message.contains(echoed), "{name} {bad:?}: {message}");
            }
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn unknown_fields_and_wrong_types_are_rejected_in_band_without_a_request()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for (name, _, _) in CONFIG_READS {
        for args in [
            object!({"bogus": 1}),
            object!({"refresh": true}),
            object!({"profile_id": "profile-0001"}),
            object!({"network_id": ["network-0001"]}),
            object!({"network_id": true}),
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
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_null_network_id_means_omitted_and_arguments_may_be_left_out() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // The network list is cached for the second call; the read itself is live both times.
    h.mount_single_network(1).await;
    h.mount_get(
        &route("network-0001", "/wpa3_per_band"),
        &config_fixture("wpa3"),
        2,
    )
    .await;

    let out = h
        .call_ok("get_wpa3_settings", object!({"network_id": null}))
        .await?;
    assert_eq!(out["network_id"], "network-0001");

    let result = h.call_without_arguments("get_wpa3_settings").await?;
    let out = common::structured(&result)?;
    assert_eq!(out["network_id"], "network-0001");
    Ok(())
}
