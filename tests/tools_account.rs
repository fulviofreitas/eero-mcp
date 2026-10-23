//! Pins the account-group tools (1 to 7): the listing and annotations, the exact GET path and
//! query, both credentials, the output shape (`data`, `network_id`, `server_time`), redaction,
//! cache and refresh call counts, default-network resolution (one, zero and several networks, all
//! three list shapes and the account fallback), every id form, and validation before any request.

mod common;

use std::time::{Duration, Instant};

use common::{Harness, authed_get, fixture, fixture_json, json_response, structured};
use rmcp::model::{CallToolRequestParams, Tool};
use rmcp::object;
use serde_json::{Value, json};
use tokio::task::JoinSet;
use wiremock::ResponseTemplate;

const REDACTED: &str = "[REDACTED]";
const GROUP: &str = "account";

fn account_fixture(name: &str) -> String {
    fixture(GROUP, name)
}

fn account_json(name: &str) -> Value {
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

// ===================== the listed tools =====================

const ACCOUNT_TOOLS: [&str; 7] = [
    "get_account",
    "list_networks",
    "get_network",
    "get_guest_network",
    "list_network_members",
    "get_network_permissions",
    "get_premium_features",
];

#[tokio::test]
async fn the_seven_account_tools_are_listed_read_only_with_titles_and_output_schemas()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for name in ACCOUNT_TOOLS {
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
    // The tools are listed sorted by name.
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
    Ok(())
}

#[tokio::test]
async fn refresh_is_offered_only_by_the_cached_account_tools() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for name in ["get_account", "list_networks", "get_network"] {
        assert!(has_property(tool(&tools, name), "refresh"), "{name}");
    }
    for name in [
        "get_guest_network",
        "list_network_members",
        "get_network_permissions",
        "get_premium_features",
    ] {
        assert!(!has_property(tool(&tools, name), "refresh"), "{name}");
    }
    // get_account and list_networks are account-level: no network_id.
    for name in ["get_account", "list_networks"] {
        assert!(!has_property(tool(&tools, name), "network_id"), "{name}");
    }
    for name in [
        "get_network",
        "get_guest_network",
        "list_network_members",
        "get_network_permissions",
        "get_premium_features",
    ] {
        let listed = tool(&tools, name);
        assert!(has_property(listed, "network_id"), "{name}");
        // Integers are accepted but the published type is string.
        assert_eq!(
            listed.input_schema["properties"]["network_id"]["type"], "string",
            "{name}"
        );
        assert!(listed.input_schema.get("required").is_none(), "{name}");
    }
    Ok(())
}

// ===================== get_account =====================

#[tokio::test]
async fn get_account_reads_the_account_with_both_credentials() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/account", &account_fixture("account"), 1)
        .await;

    let out = h.call_ok("get_account", object!({})).await?;

    let wire = account_json("account");
    assert_eq!(
        out["data"], wire["data"],
        "no deny-listed key in this fixture"
    );
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert!(out.get("network_id").is_none(), "account-level: no network");
    assert!(out.get("window").is_none());
    assert_eq!(
        out.as_object()
            .map(|o| o.keys().cloned().collect::<Vec<_>>()),
        Some(vec!["data".to_owned(), "server_time".to_owned()]),
        "only the documented members"
    );
    assert_eq!(h.targets().await, ["GET /2.2/account"]);
    Ok(())
}

#[tokio::test]
async fn get_account_works_with_the_arguments_member_omitted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/account", &account_fixture("account"), 1)
        .await;
    let result = h.call_without_arguments("get_account").await?;
    let out = structured(&result)?;
    assert_eq!(out["data"]["id"], "user-0001");
    Ok(())
}

#[tokio::test]
async fn get_account_serves_a_repeat_from_cache_and_refresh_bypasses_it() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // First call and the refresh; the repeat in between is a cache hit.
    h.mount_get("/2.2/account", &account_fixture("account"), 2)
        .await;

    for args in [
        object!({}),
        object!({}),
        object!({"refresh": true}),
        object!({"refresh": false}),
    ] {
        h.call_ok("get_account", args).await?;
    }
    assert_eq!(h.targets().await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn get_account_rejects_unknown_fields_and_wrong_types_before_any_request()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for args in [
        object!({"bogus": 1}),
        object!({"network_id": "network-0001"}),
        object!({"refresh": "yes"}),
        object!({"refresh": 1}),
    ] {
        let result = h.call("get_account", args.clone()).await?;
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

// ===================== list_networks =====================

#[tokio::test]
async fn list_networks_returns_the_unwrapped_entries_redacted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks", &account_fixture("networks"), 1)
        .await;

    let out = h.call_ok("list_networks", object!({})).await?;

    let wire = account_json("networks");
    let mut expected = wire["data"].clone();
    // Entries can carry the guest Wi-Fi password.
    expected[0]["guest_network"]["password"] = json!(REDACTED);
    assert_eq!(out["data"], expected);
    assert_eq!(
        out["data"][0]["guest_network"]["name"],
        "Example-Network Guest"
    );
    assert_eq!(out["data"][1]["name"], "Second-Network");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert!(out.get("network_id").is_none());
    assert_eq!(h.targets().await, ["GET /2.2/networks"]);
    Ok(())
}

#[tokio::test]
async fn list_networks_gives_one_array_for_every_container_shape() -> anyhow::Result<()> {
    for shape in ["networks_wrapped", "networks_data_data"] {
        let h = Harness::start().await?;
        h.mount_get("/2.2/networks", &account_fixture(shape), 1)
            .await;

        let out = h.call_ok("list_networks", object!({})).await?;

        let entries = out["data"]
            .as_array()
            .unwrap_or_else(|| panic!("{shape}: array"));
        assert_eq!(entries.len(), 2, "{shape}");
        assert_eq!(entries[0]["url"], "/2.2/networks/network-0001", "{shape}");
        assert_eq!(entries[1]["name"], "Second-Network", "{shape}");
    }
    Ok(())
}

#[tokio::test]
async fn list_networks_serves_a_repeat_from_cache_and_refresh_bypasses_it() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks", &account_fixture("networks"), 2)
        .await;

    for args in [object!({}), object!({}), object!({"refresh": true})] {
        h.call_ok("list_networks", args).await?;
    }
    Ok(())
}

#[tokio::test]
async fn list_networks_on_an_empty_list_falls_back_to_the_account() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks", &account_fixture("networks_empty"), 1)
        .await;
    h.mount_get("/2.2/account", &account_fixture("account"), 1)
        .await;

    let out = h.call_ok("list_networks", object!({})).await?;

    // rusteero synthesises the list from the account's network references.
    let entries = out["data"].as_array().expect("array");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["id"], "network-0001");
    assert_eq!(h.targets().await, ["GET /2.2/networks", "GET /2.2/account"]);
    Ok(())
}

#[tokio::test]
async fn list_networks_on_an_account_with_no_networks_is_an_empty_list() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks", &account_fixture("networks_empty"), 1)
        .await;
    h.mount_get("/2.2/account", &account_fixture("account_no_networks"), 1)
        .await;

    let out = h.call_ok("list_networks", object!({})).await?;
    assert_eq!(out["data"], json!([]));
    Ok(())
}

// ===================== get_network =====================

#[tokio::test]
async fn get_network_reads_the_network_and_echoes_it() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks/network-0001", &account_fixture("network"), 1)
        .await;

    let out = h
        .call_ok("get_network", object!({"network_id": "network-0001"}))
        .await?;

    let wire = account_json("network");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert!(
        out.get("meta").is_none(),
        "the rest of the envelope meta is dropped"
    );
    assert_eq!(out["data"]["name"], wire["data"]["name"]);
    assert_eq!(out["data"]["speed"], wire["data"]["speed"]);
    assert_eq!(h.targets().await, ["GET /2.2/networks/network-0001"]);
    Ok(())
}

#[tokio::test]
async fn get_network_redacts_wifi_and_guest_passwords_at_any_depth() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks/network-0001", &account_fixture("network"), 1)
        .await;

    let out = h
        .call_ok("get_network", object!({"network_id": "network-0001"}))
        .await?;

    let mut expected = account_json("network")["data"].clone();
    expected["guest_network"]["password"] = json!(REDACTED);
    expected["wifi_credentials"][0]["password"] = json!(REDACTED);
    expected["wifi_credentials"][1]["pre_shared_key"] = json!(REDACTED);
    assert_eq!(out["data"], expected);
    // Empty and null values stay visible; names and SSIDs are untouched.
    assert_eq!(out["data"]["wifi_credentials"][0]["psk"], "");
    assert_eq!(
        out["data"]["wifi_credentials"][1]["passphrase"],
        Value::Null
    );
    assert_eq!(
        out["data"]["wifi_credentials"][0]["ssid"],
        "Example-Network"
    );
    assert_eq!(
        out["data"]["guest_network"]["name"],
        "Example-Network Guest"
    );
    let rendered = out.to_string();
    for secret in ["guestpass000", "wifipass000", "iotpsk000"] {
        assert!(!rendered.contains(secret), "{secret} leaked");
    }
    Ok(())
}

#[tokio::test]
async fn get_network_serves_a_repeat_from_cache_and_refresh_bypasses_it() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks/network-0001", &account_fixture("network"), 2)
        .await;

    for args in [
        object!({"network_id": "network-0001"}),
        object!({"network_id": "network-0001"}),
        object!({"network_id": "network-0001", "refresh": true}),
    ] {
        h.call_ok("get_network", args).await?;
    }
    Ok(())
}

#[tokio::test]
async fn every_network_id_form_reaches_the_same_get() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    let forms = [
        json!("network-0001"),
        json!("  network-0001  "),
        json!("/2.2/networks/network-0001"),
        json!("/2.2/networks/network-0001/"),
        json!("/2.3/networks/network-0001"),
        json!(format!("{origin}/2.2/networks/network-0001")),
        json!(format!("{origin}/2.2/networks/network-0001/")),
    ];
    h.mount_get(
        "/2.2/networks/network-0001",
        &account_fixture("network"),
        u64::try_from(forms.len())?,
    )
    .await;

    for form in forms {
        // refresh forces a request per form, so each form's request is pinned.
        let out = h
            .call_ok(
                "get_network",
                object!({"network_id": form.clone(), "refresh": true}),
            )
            .await?;
        assert_eq!(out["network_id"], "network-0001", "{form}");
    }
    assert!(
        h.targets()
            .await
            .iter()
            .all(|target| target == "GET /2.2/networks/network-0001")
    );
    Ok(())
}

#[tokio::test]
async fn an_integer_network_id_is_accepted_and_rendered_in_decimal() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks/12345", &account_fixture("network"), 1)
        .await;

    let out = h
        .call_ok("get_network", object!({"network_id": 12345}))
        .await?;

    assert_eq!(out["network_id"], "12345");
    assert_eq!(h.targets().await, ["GET /2.2/networks/12345"]);
    Ok(())
}

#[tokio::test]
async fn equivalent_network_id_forms_share_one_cache_entry() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    h.mount_get("/2.2/networks/network-0001", &account_fixture("network"), 1)
        .await;

    for form in [
        "network-0001".to_owned(),
        "/2.2/networks/network-0001".to_owned(),
        format!("{origin}/2.2/networks/network-0001"),
        " network-0001 ".to_owned(),
    ] {
        h.call_ok("get_network", object!({"network_id": form}))
            .await?;
    }
    assert_eq!(
        h.targets().await.len(),
        1,
        "canonical ids hit one cache entry"
    );
    Ok(())
}

const NETWORK_TOOLS: [(&str, &str); 5] = [
    ("get_network", ""),
    ("get_guest_network", "/guestnetwork"),
    ("list_network_members", "/members"),
    ("get_network_permissions", "/permissions"),
    ("get_premium_features", ""),
];

#[tokio::test]
async fn invalid_network_ids_fail_before_any_request_on_every_network_tool() -> anyhow::Result<()> {
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
        "/2.2/networks/../hostile-0001",
        "https://api-user.e2ro.com/2.2/networks/network-0001",
        "http://other.test:1234/2.2/networks/network-0001",
    ];
    for (name, _) in NETWORK_TOOLS {
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
async fn a_foreign_origin_is_rejected_even_when_it_is_the_production_host() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    let err = h
        .call_err(
            "get_network",
            object!({"network_id": "https://api-user.e2ro.com/2.2/networks/network-0001"}),
        )
        .await?;
    assert_eq!(err["error"]["code"], "invalid_argument");
    assert_eq!(err["error"]["field"], "network_id");
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_null_network_id_means_omitted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get("/2.2/networks/network-0001", &account_fixture("network"), 1)
        .await;
    let out = h
        .call_ok("get_network", object!({"network_id": null}))
        .await?;
    assert_eq!(out["network_id"], "network-0001");
    Ok(())
}

// ===================== get_guest_network =====================

#[tokio::test]
async fn get_guest_network_reads_guestnetwork_and_redacts_the_password() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/guestnetwork",
        &account_fixture("guest_network"),
        1,
    )
    .await;

    let out = h
        .call_ok("get_guest_network", object!({"network_id": "network-0001"}))
        .await?;

    let wire = account_json("guest_network");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(
        out["data"],
        json!({"enabled": true, "name": "Example-Network Guest", "password": REDACTED})
    );
    assert!(!out.to_string().contains("guestpass000"));
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/guestnetwork"]
    );
    Ok(())
}

// ===================== list_network_members =====================

#[tokio::test]
async fn list_network_members_reads_members() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/members",
        &account_fixture("members"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "list_network_members",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = account_json("members");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/members"]
    );
    Ok(())
}

// ===================== get_network_permissions =====================

#[tokio::test]
async fn get_network_permissions_reads_permissions() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/permissions",
        &account_fixture("permissions"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_network_permissions",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = account_json("permissions");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/permissions"]
    );
    Ok(())
}

// ===================== get_premium_features =====================

#[tokio::test]
async fn get_premium_features_reads_the_entitlement_features() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/entitlements/networks/network-0001/features",
        &account_fixture("entitlement_features"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_premium_features",
            object!({"network_id": "network-0001"}),
        )
        .await?;

    let wire = account_json("entitlement_features");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(
        h.targets().await,
        ["GET /2.2/entitlements/networks/network-0001/features"]
    );
    Ok(())
}

// ===================== both credentials, no query, on every tool =====================

#[tokio::test]
async fn every_account_read_sends_both_credentials_and_no_query() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let routes = [
        ("/2.2/account", "account"),
        ("/2.2/networks", "networks"),
        ("/2.2/networks/network-0001", "network"),
        ("/2.2/networks/network-0001/guestnetwork", "guest_network"),
        ("/2.2/networks/network-0001/members", "members"),
        ("/2.2/networks/network-0001/permissions", "permissions"),
        (
            "/2.2/entitlements/networks/network-0001/features",
            "entitlement_features",
        ),
    ];
    // authed_get requires both credential headers and pins the query to exactly nothing.
    for (route, name) in routes {
        authed_get(route)
            .respond_with(json_response(&account_fixture(name)))
            .expect(1)
            .mount(&h.mock)
            .await;
    }

    h.call_ok("get_account", object!({})).await?;
    h.call_ok("list_networks", object!({})).await?;
    for (tool, _) in NETWORK_TOOLS {
        h.call_ok(tool, object!({"network_id": "network-0001"}))
            .await?;
    }
    for request in h.received().await {
        assert_eq!(request.url.query(), None, "{}", request.url);
        assert_eq!(request.method.as_str(), "GET");
    }
    Ok(())
}

// ===================== default network resolution =====================

fn suffix_route(suffix: &str, tool: &str) -> String {
    if tool == "get_premium_features" {
        "/2.2/entitlements/networks/network-0001/features".to_owned()
    } else {
        format!("/2.2/networks/network-0001{suffix}")
    }
}

#[tokio::test]
async fn an_omitted_network_id_uses_the_only_network_on_every_network_tool() -> anyhow::Result<()> {
    for (tool_name, suffix) in NETWORK_TOOLS {
        let h = Harness::start().await?;
        h.mount_get("/2.2/networks", &account_fixture("networks_one"), 1)
            .await;
        let route = suffix_route(suffix, tool_name);
        h.mount_get(&route, &account_fixture("network"), 1).await;

        let out = h.call_ok(tool_name, object!({})).await?;

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
async fn default_resolution_reads_all_three_list_shapes() -> anyhow::Result<()> {
    for shape in [
        "networks_one",
        "networks_one_wrapped",
        "networks_one_data_data",
    ] {
        let h = Harness::start().await?;
        h.mount_get("/2.2/networks", &account_fixture(shape), 1)
            .await;
        h.mount_get(
            "/2.2/networks/network-0001/guestnetwork",
            &account_fixture("guest_network"),
            1,
        )
        .await;

        let out = h.call_ok("get_guest_network", object!({})).await?;
        assert_eq!(out["network_id"], "network-0001", "{shape}");
    }
    Ok(())
}

#[tokio::test]
async fn default_resolution_uses_the_account_fallback_for_an_empty_list() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks", &account_fixture("networks_empty"), 1)
        .await;
    h.mount_get("/2.2/account", &account_fixture("account_one_network"), 1)
        .await;
    h.mount_get(
        "/2.2/networks/network-0001/members",
        &account_fixture("members"),
        1,
    )
    .await;

    let out = h.call_ok("list_network_members", object!({})).await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks",
            "GET /2.2/account",
            "GET /2.2/networks/network-0001/members"
        ]
    );
    Ok(())
}

#[tokio::test]
async fn default_resolution_reads_the_cached_list_only_once_within_the_ttl() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks", &account_fixture("networks_one"), 1)
        .await;
    h.mount_get(
        "/2.2/networks/network-0001/members",
        &account_fixture("members"),
        2,
    )
    .await;

    h.call_ok("list_network_members", object!({})).await?;
    h.call_ok("list_network_members", object!({})).await?;

    let networks_reads = h
        .targets()
        .await
        .iter()
        .filter(|target| *target == "GET /2.2/networks")
        .count();
    assert_eq!(networks_reads, 1);
    Ok(())
}

#[tokio::test]
async fn default_resolution_ignores_the_refresh_flag_of_the_tool() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // get_network with refresh reads the network fresh, but the list stays cached.
    h.mount_get("/2.2/networks", &account_fixture("networks_one"), 1)
        .await;
    h.mount_get("/2.2/networks/network-0001", &account_fixture("network"), 2)
        .await;

    h.call_ok("get_network", object!({"refresh": true})).await?;
    h.call_ok("get_network", object!({"refresh": true})).await?;
    Ok(())
}

#[tokio::test]
async fn several_networks_without_a_network_id_list_each_id_and_name() -> anyhow::Result<()> {
    for tool_name in ["get_network", "get_guest_network", "get_premium_features"] {
        let h = Harness::start().await?;
        h.mount_get("/2.2/networks", &account_fixture("networks"), 1)
            .await;

        let err = h.call_err(tool_name, object!({})).await?;

        assert_eq!(err["error"]["code"], "invalid_argument", "{tool_name}");
        assert_eq!(err["error"]["field"], "network_id", "{tool_name}");
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
            "{tool_name}: nothing is read for a network chosen by the server"
        );
    }
    Ok(())
}

#[tokio::test]
async fn several_networks_in_every_list_shape_are_ambiguous() -> anyhow::Result<()> {
    for shape in ["networks_wrapped", "networks_data_data"] {
        let h = Harness::start().await?;
        h.mount_get("/2.2/networks", &account_fixture(shape), 1)
            .await;
        let err = h.call_err("get_guest_network", object!({})).await?;
        assert_eq!(err["error"]["code"], "invalid_argument", "{shape}");
        assert_eq!(err["error"]["field"], "network_id", "{shape}");
    }
    Ok(())
}

#[tokio::test]
async fn the_ambiguity_is_resolved_by_passing_one_of_the_listed_ids() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks", &account_fixture("networks"), 1)
        .await;
    h.mount_get(
        "/2.2/networks/network-0002/guestnetwork",
        &account_fixture("guest_network"),
        1,
    )
    .await;

    assert!(h.call_err("get_guest_network", object!({})).await.is_ok());
    let out = h
        .call_ok("get_guest_network", object!({"network_id": "network-0002"}))
        .await?;
    assert_eq!(out["network_id"], "network-0002");
    Ok(())
}

#[tokio::test]
async fn no_networks_at_all_is_not_found() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get("/2.2/networks", &account_fixture("networks_empty"), 1)
        .await;
    h.mount_get("/2.2/account", &account_fixture("account_no_networks"), 1)
        .await;

    let err = h.call_err("get_network", object!({})).await?;

    assert_eq!(err["error"]["code"], "not_found");
    assert_eq!(err["error"]["message"], "no networks on this account");
    assert!(err["error"].get("field").is_none());
    assert_eq!(h.targets().await, ["GET /2.2/networks", "GET /2.2/account"]);
    Ok(())
}

#[tokio::test]
async fn an_explicit_network_id_never_reads_the_network_list() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/members",
        &account_fixture("members"),
        1,
    )
    .await;
    h.call_ok(
        "list_network_members",
        object!({"network_id": "network-0001"}),
    )
    .await?;
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/members"]
    );
    Ok(())
}

// ===================== concurrency =====================

#[tokio::test]
async fn upstream_reads_are_capped_at_four_at_a_time() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let delay = Duration::from_millis(800);
    authed_get("/2.2/networks/network-0001/members")
        .respond_with(json_response(&account_fixture("members")).set_delay(delay))
        .expect(8)
        .mount(&h.mock)
        .await;

    let peer = h.client.peer().clone();
    let mut calls = JoinSet::new();
    for _ in 0..8 {
        let peer = peer.clone();
        calls.spawn(async move {
            peer.call_tool(
                CallToolRequestParams::new("list_network_members")
                    .with_arguments(object!({"network_id": "network-0001"})),
            )
            .await
        });
    }

    // The first wave: four requests reach the wire while the other four wait for a permit. The
    // responses are held for `delay`, so no fifth request can start before then.
    let waited = Instant::now();
    while h.received().await.len() < 4 {
        assert!(
            waited.elapsed() < Duration::from_secs(10),
            "four requests in flight"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(delay / 4).await;
    assert_eq!(
        h.received().await.len(),
        4,
        "exactly four upstream reads are in flight at once"
    );

    while let Some(joined) = calls.join_next().await {
        let result = joined??;
        assert_eq!(result.is_error, Some(false));
    }
    assert_eq!(
        h.received().await.len(),
        8,
        "the second wave ran once permits were free"
    );
    Ok(())
}

// ===================== a response with a different status =====================

#[tokio::test]
async fn the_credential_headers_are_required_by_the_mocks() -> anyhow::Result<()> {
    // Sanity check of the harness itself: a mock demanding another token never matches, so the
    // server's request (carrying test-token) gets wiremock's 404 and maps to not_found.
    let h = Harness::start().await?;
    common::authed_get("/2.2/account")
        .and(common::user_token_header_for("some-other-token"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&h.mock)
        .await;
    let err = h.call_err("get_account", object!({})).await?;
    assert_eq!(err["error"]["code"], "not_found");
    Ok(())
}
