//! Pins the profiles-group tools (15 to 18): the listing and annotations, the exact GET path and
//! query, both credentials, the output shape (`data`, `network_id`, `server_time`), cache and
//! refresh call counts for the two cached tools, default-network resolution, every `profile_id`
//! form (including a path under another network, which is rejected), eero Plus gating, and
//! validation before any request.

mod common;

use common::{Harness, authed_get, fixture, fixture_json, json_response, json_status};
use rmcp::model::Tool;
use rmcp::object;
use serde_json::{Value, json};

const GROUP: &str = "profiles";

fn profiles_fixture(name: &str) -> String {
    fixture(GROUP, name)
}

fn profiles_json(name: &str) -> Value {
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

const NETWORK: &str = "/2.2/networks/network-0001";
const PROFILES_ROUTE: &str = "/2.2/networks/network-0001/profiles";
const PROFILE_ROUTE: &str = "/2.2/networks/network-0001/profiles/profile-0001";
const SCHEDULES_ROUTE: &str = "/2.2/networks/network-0001/profiles/profile-0001/schedules";
const APPLICATIONS_ROUTE: &str =
    "/2.2/networks/network-0001/dns_policies/profiles/profile-0001/applications";

/// The three tools that forward a `profile_id`, with the route each one reads and its fixture.
const PROFILE_READS: [(&str, &str, &str); 3] = [
    ("get_profile", PROFILE_ROUTE, "profile"),
    ("list_profile_schedules", SCHEDULES_ROUTE, "schedules"),
    (
        "get_profile_blocked_apps",
        APPLICATIONS_ROUTE,
        "blocked_apps",
    ),
];

// ===================== the listed tools =====================

const PROFILE_TOOLS: [&str; 4] = [
    "list_profiles",
    "get_profile",
    "list_profile_schedules",
    "get_profile_blocked_apps",
];

#[tokio::test]
async fn the_four_profile_tools_are_listed_read_only_with_titles_and_output_schemas()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for name in PROFILE_TOOLS {
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
async fn the_descriptions_state_the_eero_plus_gating_of_the_blocked_apps_tool() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    let description = tool(&tools, "get_profile_blocked_apps")
        .description
        .as_deref()
        .unwrap_or_default();
    assert!(description.contains("eero Plus"), "{description}");
    assert!(description.contains("premium_required"), "{description}");
    for name in ["list_profiles", "get_profile", "list_profile_schedules"] {
        let description = tool(&tools, name)
            .description
            .as_deref()
            .unwrap_or_default();
        assert!(!description.contains("eero Plus"), "{name}: {description}");
    }
    Ok(())
}

#[tokio::test]
async fn refresh_is_offered_only_by_the_two_cached_profile_tools() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for name in ["list_profiles", "get_profile"] {
        assert!(has_property(tool(&tools, name), "refresh"), "{name}");
    }
    for name in ["list_profile_schedules", "get_profile_blocked_apps"] {
        assert!(!has_property(tool(&tools, name), "refresh"), "{name}");
    }
    Ok(())
}

#[tokio::test]
async fn profile_id_is_required_on_exactly_the_three_child_id_tools() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;

    for name in PROFILE_TOOLS {
        let listed = tool(&tools, name);
        assert!(has_property(listed, "network_id"), "{name}");
        assert_eq!(
            listed.input_schema["properties"]["network_id"]["type"], "string",
            "{name}"
        );
        if name == "list_profiles" {
            assert!(!has_property(listed, "profile_id"), "{name}");
            assert!(listed.input_schema.get("required").is_none(), "{name}");
        } else {
            // Integers are accepted but the published type is string.
            assert_eq!(
                listed.input_schema["properties"]["profile_id"]["type"], "string",
                "{name}"
            );
            assert_eq!(
                listed.input_schema.get("required"),
                Some(&json!(["profile_id"])),
                "{name}: only profile_id is required"
            );
        }
    }
    Ok(())
}

// ===================== list_profiles =====================

#[tokio::test]
async fn list_profiles_reads_the_profile_list_with_both_credentials() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(PROFILES_ROUTE, &profiles_fixture("profiles"), 1)
        .await;

    let out = h
        .call_ok("list_profiles", object!({"network_id": "network-0001"}))
        .await?;

    let wire = profiles_json("profiles");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"], "no deny-listed key here");
    assert_eq!(out["data"][0]["name"], "Kids");
    assert_eq!(out["data"][1]["paused"], true);
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
    assert_eq!(h.targets().await, [format!("GET {PROFILES_ROUTE}")]);
    Ok(())
}

#[tokio::test]
async fn list_profiles_serves_a_repeat_from_cache_and_refresh_bypasses_it() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // The first call and the refresh; the repeats in between are cache hits.
    h.mount_get(PROFILES_ROUTE, &profiles_fixture("profiles"), 2)
        .await;

    for args in [
        object!({"network_id": "network-0001"}),
        object!({"network_id": "network-0001"}),
        object!({"network_id": "network-0001", "refresh": false}),
        object!({"network_id": "network-0001", "refresh": true}),
    ] {
        h.call_ok("list_profiles", args).await?;
    }
    assert_eq!(h.targets().await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn list_profiles_equivalent_network_id_forms_share_one_cache_entry() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    h.mount_get(PROFILES_ROUTE, &profiles_fixture("profiles"), 1)
        .await;

    for form in [
        "network-0001".to_owned(),
        "/2.2/networks/network-0001".to_owned(),
        format!("{origin}/2.2/networks/network-0001/"),
        " network-0001 ".to_owned(),
    ] {
        let out = h
            .call_ok("list_profiles", object!({"network_id": form}))
            .await?;
        assert_eq!(out["network_id"], "network-0001");
    }
    assert_eq!(h.targets().await.len(), 1);
    Ok(())
}

#[tokio::test]
async fn list_profiles_uses_the_only_network_when_network_id_is_omitted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get(PROFILES_ROUTE, &profiles_fixture("profiles"), 1)
        .await;

    let out = h.call_ok("list_profiles", object!({})).await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks".to_owned(),
            format!("GET {PROFILES_ROUTE}")
        ]
    );
    Ok(())
}

#[tokio::test]
async fn list_profiles_with_several_networks_and_no_network_id_lists_them() -> anyhow::Result<()> {
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

    let err = h.call_err("list_profiles", object!({})).await?;

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
    assert_eq!(h.targets().await, ["GET /2.2/networks"]);
    Ok(())
}

#[tokio::test]
async fn list_profiles_rejects_bad_arguments_before_any_request() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for bad in [
        "",
        "   ",
        "../hostile-0001",
        "a/b",
        "/2.2/eeros/eero-0001",
        "/2.2/networks/network-0001/profiles",
        "https://api-user.e2ro.com/2.2/networks/network-0001",
    ] {
        let err = h
            .call_err("list_profiles", object!({"network_id": bad}))
            .await?;
        assert_eq!(err["error"]["code"], "invalid_argument", "{bad:?}");
        assert_eq!(err["error"]["field"], "network_id", "{bad:?}");
        let message = err["error"]["message"].as_str().unwrap_or_default();
        for echoed in ["hostile", "e2ro", "eero-0001", "profiles"] {
            assert!(!message.contains(echoed), "{bad:?}: {message}");
        }
    }
    // rmcp rejects unknown fields and wrong types in-band, with its own text.
    for args in [
        object!({"bogus": 1}),
        object!({"profile_id": "profile-0001"}),
        object!({"refresh": "yes"}),
        object!({"refresh": 1}),
    ] {
        let result = h.call("list_profiles", args.clone()).await?;
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

// ===================== get_profile =====================

#[tokio::test]
async fn get_profile_reads_one_profile_and_echoes_the_network() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(PROFILE_ROUTE, &profiles_fixture("profile"), 1)
        .await;

    let out = h
        .call_ok(
            "get_profile",
            object!({"network_id": "network-0001", "profile_id": "profile-0001"}),
        )
        .await?;

    let wire = profiles_json("profile");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert!(out.get("meta").is_none(), "the rest of the meta is dropped");
    assert_eq!(out["data"], wire["data"], "no deny-listed key here");
    assert_eq!(out["data"]["name"], "Kids");
    assert_eq!(
        out["data"]["devices"][0]["mac"], "aa:bb:cc:00:00:01",
        "device addresses are not secrets"
    );
    assert_eq!(h.targets().await, [format!("GET {PROFILE_ROUTE}")]);
    Ok(())
}

#[tokio::test]
async fn get_profile_serves_a_repeat_from_cache_and_refresh_bypasses_it() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(PROFILE_ROUTE, &profiles_fixture("profile"), 2)
        .await;

    for args in [
        object!({"network_id": "network-0001", "profile_id": "profile-0001"}),
        object!({"network_id": "network-0001", "profile_id": "profile-0001"}),
        object!({"network_id": "network-0001", "profile_id": "profile-0001", "refresh": false}),
        object!({"network_id": "network-0001", "profile_id": "profile-0001", "refresh": true}),
    ] {
        h.call_ok("get_profile", args).await?;
    }
    assert_eq!(h.targets().await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn get_profile_caches_each_profile_separately() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(PROFILE_ROUTE, &profiles_fixture("profile"), 1)
        .await;
    h.mount_get(
        "/2.2/networks/network-0001/profiles/profile-0002",
        &profiles_fixture("profile"),
        1,
    )
    .await;

    for profile in [
        "profile-0001",
        "profile-0002",
        "profile-0001",
        "profile-0002",
    ] {
        h.call_ok(
            "get_profile",
            object!({"network_id": "network-0001", "profile_id": profile}),
        )
        .await?;
    }
    assert_eq!(h.targets().await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn every_profile_id_form_reaches_the_same_get() -> anyhow::Result<()> {
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
        json!(format!(
            "{origin}/2.2/networks/network-0001/profiles/profile-0001/"
        )),
    ];
    h.mount_get(
        PROFILE_ROUTE,
        &profiles_fixture("profile"),
        u64::try_from(forms.len())?,
    )
    .await;

    for form in forms {
        // refresh forces a request per form, so each form's request is pinned.
        let out = h
            .call_ok(
                "get_profile",
                object!({"network_id": "network-0001", "profile_id": form.clone(), "refresh": true}),
            )
            .await?;
        assert_eq!(out["network_id"], "network-0001", "{form}");
    }
    assert!(
        h.targets()
            .await
            .iter()
            .all(|target| *target == format!("GET {PROFILE_ROUTE}"))
    );
    Ok(())
}

#[tokio::test]
async fn equivalent_profile_id_forms_share_one_cache_entry() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let origin = h.origin();
    h.mount_get(PROFILE_ROUTE, &profiles_fixture("profile"), 1)
        .await;

    for form in [
        "profile-0001".to_owned(),
        "/2.2/networks/network-0001/profiles/profile-0001".to_owned(),
        format!("{origin}/2.2/networks/network-0001/profiles/profile-0001"),
        " profile-0001 ".to_owned(),
    ] {
        h.call_ok(
            "get_profile",
            object!({"network_id": "network-0001", "profile_id": form}),
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
async fn an_integer_profile_id_is_accepted_and_rendered_in_decimal() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(
        "/2.2/networks/network-0001/profiles/12345",
        &profiles_fixture("profile"),
        1,
    )
    .await;

    let out = h
        .call_ok(
            "get_profile",
            object!({"network_id": "network-0001", "profile_id": 12345}),
        )
        .await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        ["GET /2.2/networks/network-0001/profiles/12345"]
    );
    Ok(())
}

#[tokio::test]
async fn get_profile_uses_the_only_network_when_network_id_is_omitted() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get(PROFILE_ROUTE, &profiles_fixture("profile"), 1)
        .await;

    let out = h
        .call_ok("get_profile", object!({"profile_id": "profile-0001"}))
        .await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks".to_owned(),
            format!("GET {PROFILE_ROUTE}")
        ]
    );
    Ok(())
}

#[tokio::test]
async fn a_profile_path_is_checked_against_the_default_network_after_it_is_resolved()
-> anyhow::Result<()> {
    // The path names the account's only network: accepted, after the one list read.
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get(PROFILE_ROUTE, &profiles_fixture("profile"), 1)
        .await;
    let out = h
        .call_ok(
            "get_profile",
            object!({"profile_id": "/2.2/networks/network-0001/profiles/profile-0001"}),
        )
        .await?;
    assert_eq!(out["network_id"], "network-0001");

    // The path names another network: rejected after the list read, before the profile read.
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    let err = h
        .call_err(
            "get_profile",
            object!({"profile_id": "/2.2/networks/network-0009/profiles/profile-0001"}),
        )
        .await?;
    assert_eq!(err["error"]["code"], "invalid_argument");
    assert_eq!(err["error"]["field"], "profile_id");
    let message = err["error"]["message"].as_str().unwrap_or_default();
    assert!(!message.contains("network-0009"), "{message}");
    assert_eq!(h.targets().await, ["GET /2.2/networks"]);
    Ok(())
}

#[tokio::test]
async fn a_profile_path_under_another_network_is_rejected_with_zero_requests() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;
    let origin = h.origin();

    for tool_name in [
        "get_profile",
        "list_profile_schedules",
        "get_profile_blocked_apps",
    ] {
        for foreign in [
            "/2.2/networks/network-0009/profiles/profile-0001".to_owned(),
            format!("{origin}/2.2/networks/network-0009/profiles/profile-0001"),
        ] {
            let err = h
                .call_err(
                    tool_name,
                    object!({"network_id": "network-0001", "profile_id": foreign.clone()}),
                )
                .await?;
            assert_eq!(err["error"]["code"], "invalid_argument", "{tool_name}");
            assert_eq!(err["error"]["field"], "profile_id", "{tool_name}");
            let message = err["error"]["message"].as_str().unwrap_or_default();
            assert!(!message.is_empty());
            assert!(!message.contains("network-0009"), "{tool_name}: {message}");
            assert!(!message.contains(&origin), "{tool_name}: {message}");
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

// ===================== profile_id validation, on the three child-id tools =====================

#[tokio::test]
async fn invalid_profile_ids_fail_before_any_request_on_every_child_id_tool() -> anyhow::Result<()>
{
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
        "/2.2/networks/network-0001/devices/device-0001",
        "/2.2/networks/network-0001/profiles/profile-0001/schedules",
        "/2.2/networks/network-0001/profiles/../hostile-0001",
        "/2.2/eeros/eero-0001",
        "https://api-user.e2ro.com/2.2/networks/network-0001/profiles/profile-0001",
        "http://other.test:1234/2.2/networks/network-0001/profiles/profile-0001",
    ];
    for (name, _, _) in PROFILE_READS {
        for bad in bad_ids {
            // With and without a network_id: the profile id is checked before the network list
            // would be read, so neither form sends a request.
            for args in [
                object!({"network_id": "network-0001", "profile_id": bad}),
                object!({"profile_id": bad}),
            ] {
                let err = h.call_err(name, args).await?;
                assert_eq!(err["error"]["code"], "invalid_argument", "{name} {bad:?}");
                assert_eq!(err["error"]["field"], "profile_id", "{name} {bad:?}");
                let message = err["error"]["message"].as_str().unwrap_or_default();
                assert!(!message.is_empty());
                for echoed in ["hostile", "other.test", "e2ro", "eero-0001", "device-0001"] {
                    assert!(!message.contains(echoed), "{name} {bad:?}: {message}");
                }
            }
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn invalid_network_ids_fail_before_any_request_on_every_child_id_tool() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for (name, _, _) in PROFILE_READS {
        for bad in ["", "   ", "../hostile-0001", "/2.2/eeros/eero-0001"] {
            let err = h
                .call_err(
                    name,
                    object!({"network_id": bad, "profile_id": "profile-0001"}),
                )
                .await?;
            assert_eq!(err["error"]["code"], "invalid_argument", "{name} {bad:?}");
            assert_eq!(err["error"]["field"], "network_id", "{name} {bad:?}");
        }
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn a_missing_null_or_mistyped_profile_id_is_rejected_in_band_without_a_request()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for (name, _, _) in PROFILE_READS {
        for args in [
            object!({}),
            object!({"network_id": "network-0001"}),
            object!({"network_id": "network-0001", "profile_id": null}),
            object!({"network_id": "network-0001", "profile_id": true}),
            object!({"network_id": "network-0001", "profile_id": ["profile-0001"]}),
            object!({"network_id": "network-0001", "profile_id": "profile-0001", "bogus": 1}),
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
    let result = h.call_without_arguments("get_profile").await?;
    assert_eq!(result.is_error, Some(true));
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn refresh_is_rejected_on_the_two_uncached_child_id_tools() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.expect_no_requests().await;

    for name in ["list_profile_schedules", "get_profile_blocked_apps"] {
        let result = h
            .call(
                name,
                object!({"network_id": "network-0001", "profile_id": "profile-0001", "refresh": true}),
            )
            .await?;
        assert_eq!(result.is_error, Some(true), "{name}");
        let text = result.content[0].as_text().expect("text").text.clone();
        assert!(
            text.starts_with("failed to deserialize parameters"),
            "{name}: {text}"
        );
    }
    h.assert_no_requests().await;
    Ok(())
}

// ===================== list_profile_schedules =====================

#[tokio::test]
async fn list_profile_schedules_reads_the_schedules_of_one_profile() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(SCHEDULES_ROUTE, &profiles_fixture("schedules"), 1)
        .await;

    let out = h
        .call_ok(
            "list_profile_schedules",
            object!({"network_id": "network-0001", "profile_id": "profile-0001"}),
        )
        .await?;

    let wire = profiles_json("schedules");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["data"][0]["name"], "Bedtime");
    assert_eq!(out["data"][1]["enabled"], false);
    assert_eq!(h.targets().await, [format!("GET {SCHEDULES_ROUTE}")]);
    Ok(())
}

#[tokio::test]
async fn list_profile_schedules_is_not_cached() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(SCHEDULES_ROUTE, &profiles_fixture("schedules"), 2)
        .await;

    for _ in 0..2 {
        h.call_ok(
            "list_profile_schedules",
            object!({"network_id": "network-0001", "profile_id": "profile-0001"}),
        )
        .await?;
    }
    assert_eq!(h.targets().await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn list_profile_schedules_accepts_a_profile_path_and_an_omitted_network() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get(SCHEDULES_ROUTE, &profiles_fixture("schedules"), 1)
        .await;

    let out = h
        .call_ok(
            "list_profile_schedules",
            object!({"profile_id": "/2.2/networks/network-0001/profiles/profile-0001"}),
        )
        .await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks".to_owned(),
            format!("GET {SCHEDULES_ROUTE}")
        ]
    );
    Ok(())
}

#[tokio::test]
async fn list_profile_schedules_of_an_unknown_profile_is_not_found_without_echoing_it()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    authed_get("/2.2/networks/network-0001/profiles/profile-0404/schedules")
        .respond_with(json_status(
            404,
            &json!({"meta": {"code": 404, "error": "error.resource.not_found"}, "data": {}}),
        ))
        .expect(1)
        .mount(&h.mock)
        .await;

    let err = h
        .call_err(
            "list_profile_schedules",
            object!({"network_id": "network-0001", "profile_id": "profile-0404"}),
        )
        .await?;

    assert_eq!(err["error"]["code"], "not_found");
    assert_eq!(err["error"]["upstream_status"], 404);
    let rendered = err.to_string();
    for leak in ["profile-0404", "network-0001", "/2.2/"] {
        assert!(!rendered.contains(leak), "{leak} leaked: {rendered}");
    }
    Ok(())
}

// ===================== get_profile_blocked_apps =====================

#[tokio::test]
async fn get_profile_blocked_apps_reads_the_application_policy_of_one_profile() -> anyhow::Result<()>
{
    let h = Harness::start().await?;
    h.mount_get(APPLICATIONS_ROUTE, &profiles_fixture("blocked_apps"), 1)
        .await;

    let out = h
        .call_ok(
            "get_profile_blocked_apps",
            object!({"network_id": "network-0001", "profile_id": "profile-0001"}),
        )
        .await?;

    let wire = profiles_json("blocked_apps");
    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(out["server_time"], wire["meta"]["server_time"]);
    assert_eq!(out["data"], wire["data"]);
    assert_eq!(out["data"]["applications"][0]["is_blocked"], true);
    assert_eq!(h.targets().await, [format!("GET {APPLICATIONS_ROUTE}")]);
    Ok(())
}

#[tokio::test]
async fn get_profile_blocked_apps_is_not_cached() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_get(APPLICATIONS_ROUTE, &profiles_fixture("blocked_apps"), 2)
        .await;

    for _ in 0..2 {
        h.call_ok(
            "get_profile_blocked_apps",
            object!({"network_id": "network-0001", "profile_id": "profile-0001"}),
        )
        .await?;
    }
    assert_eq!(h.targets().await.len(), 2);
    Ok(())
}

#[tokio::test]
async fn get_profile_blocked_apps_without_eero_plus_is_premium_required() -> anyhow::Result<()> {
    for status in [403, 404] {
        let h = Harness::start().await?;
        authed_get(APPLICATIONS_ROUTE)
            .respond_with(json_status(
                status,
                &json!({
                    "meta": {"code": status, "error": "error.premium.user_not_subscribed"},
                    "data": {}
                }),
            ))
            .expect(1)
            .mount(&h.mock)
            .await;

        let err = h
            .call_err(
                "get_profile_blocked_apps",
                object!({"network_id": "network-0001", "profile_id": "profile-0001"}),
            )
            .await?;

        assert_eq!(err["error"]["code"], "premium_required", "status {status}");
        assert_eq!(err["error"]["upstream_status"], status, "status {status}");
        assert_eq!(
            err["error"]["upstream_code"],
            "error.premium.user_not_subscribed"
        );
        let message = err["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains("eero Plus"), "{message}");
        let rendered = err.to_string();
        for leak in ["profile-0001", "network-0001", "/2.2/"] {
            assert!(!rendered.contains(leak), "{leak} leaked: {rendered}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn get_profile_blocked_apps_uses_the_only_network_when_network_id_is_omitted()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    h.mount_single_network(1).await;
    h.mount_get(APPLICATIONS_ROUTE, &profiles_fixture("blocked_apps"), 1)
        .await;

    let out = h
        .call_ok(
            "get_profile_blocked_apps",
            object!({"profile_id": "profile-0001"}),
        )
        .await?;

    assert_eq!(out["network_id"], "network-0001");
    assert_eq!(
        h.targets().await,
        [
            "GET /2.2/networks".to_owned(),
            format!("GET {APPLICATIONS_ROUTE}")
        ]
    );
    Ok(())
}

// ===================== both credentials, no query, on every tool =====================

#[tokio::test]
async fn every_profile_read_sends_both_credentials_and_no_query() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    // authed_get requires both credential headers and pins the query to exactly nothing.
    authed_get(PROFILES_ROUTE)
        .respond_with(json_response(&profiles_fixture("profiles")))
        .expect(1)
        .mount(&h.mock)
        .await;
    for (_, route, name) in PROFILE_READS {
        authed_get(route)
            .respond_with(json_response(&profiles_fixture(name)))
            .expect(1)
            .mount(&h.mock)
            .await;
    }

    h.call_ok("list_profiles", object!({"network_id": "network-0001"}))
        .await?;
    for (tool_name, _, _) in PROFILE_READS {
        h.call_ok(
            tool_name,
            object!({"network_id": "network-0001", "profile_id": "profile-0001"}),
        )
        .await?;
    }
    let received = h.received().await;
    assert_eq!(received.len(), 4);
    for request in received {
        assert_eq!(request.url.query(), None, "{}", request.url);
        assert_eq!(request.method.as_str(), "GET");
        assert!(request.url.path().starts_with(NETWORK), "{}", request.url);
    }
    Ok(())
}
