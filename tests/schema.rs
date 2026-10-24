//! The published tool surface, checked generically over *every* registered tool, so a tool added
//! by any group is held to the same rules without touching this file: read-only annotations, a
//! title, a description, an `outputSchema`, and portable input schemas (object root, no unknown
//! fields, no type arrays, no `default` keyword, every property described). Plus the server info.
//!
//! The registered tools must be exactly the 40-tool catalogue below: no stray, no duplicate and no
//! missing tool.

mod common;

use common::Harness;
use rmcp::model::{CallToolRequestParams, ErrorCode, ProtocolVersion, Tool};
use rmcp::{ServiceError, object};
use serde_json::{Map, Value, json};

/// The 40 catalogue tools, by number.
const CATALOGUE: [&str; 40] = [
    "get_account",
    "list_networks",
    "get_network",
    "get_guest_network",
    "list_network_members",
    "get_network_permissions",
    "get_premium_features",
    "list_eeros",
    "get_eero",
    "list_eero_connections",
    "list_devices",
    "get_device",
    "list_blocked_devices",
    "get_transfer_stats",
    "list_profiles",
    "get_profile",
    "list_profile_schedules",
    "get_profile_blocked_apps",
    "list_speed_tests",
    "get_diagnostics",
    "get_firmware_updates",
    "get_channel_utilization",
    "get_network_scan",
    "list_activity_events",
    "list_notifications",
    "list_port_forwards",
    "list_dhcp_reservations",
    "get_subnets",
    "get_wpa3_settings",
    "get_fast_transition",
    "get_content_filter",
    "get_backup_internet",
    "get_data_usage",
    "get_devices_data_usage",
    "get_device_data_usage",
    "get_eeros_data_usage",
    "get_profile_data_usage",
    "get_insights",
    "get_devices_insights",
    "get_device_insights",
];

/// The eight tools backed by rusteero's cached getters: the only ones that take `refresh`.
const CACHED: [&str; 8] = [
    "get_account",
    "list_networks",
    "get_network",
    "list_eeros",
    "list_devices",
    "get_device",
    "list_profiles",
    "get_profile",
];

async fn tools() -> anyhow::Result<(Harness, Vec<Tool>)> {
    let h = Harness::start().await?;
    let tools = h.client.list_all_tools().await?;
    Ok((h, tools))
}

fn schema_value(schema: &Map<String, Value>) -> Value {
    Value::Object(schema.clone())
}

/// Walks a JSON schema and calls `visit` on every schema object, with a path for messages. The
/// maps under `properties`, `$defs` and `definitions` hold *named* schemas: their keys are names,
/// not keywords.
fn walk(path: &str, schema: &Value, visit: &mut impl FnMut(&str, &Map<String, Value>)) {
    let Value::Object(object) = schema else {
        return;
    };
    visit(path, object);
    for (key, value) in object {
        match key.as_str() {
            "properties" | "$defs" | "definitions" | "patternProperties" => {
                if let Value::Object(named) = value {
                    for (name, child) in named {
                        walk(&format!("{path}/{key}/{name}"), child, visit);
                    }
                }
            }
            "enum" | "const" | "examples" | "default" | "required" => {}
            _ => match value {
                Value::Object(_) => walk(&format!("{path}/{key}"), value, visit),
                Value::Array(items) => {
                    for (index, item) in items.iter().enumerate() {
                        walk(&format!("{path}/{key}/{index}"), item, visit);
                    }
                }
                _ => {}
            },
        }
    }
}

// ===================== the registered tools =====================

#[tokio::test]
async fn the_registered_tools_are_exactly_the_catalogue() -> anyhow::Result<()> {
    let (_h, tools) = tools().await?;
    assert!(!tools.is_empty());
    let mut seen = std::collections::BTreeSet::new();
    for tool in &tools {
        assert!(
            CATALOGUE.contains(&tool.name.as_ref()),
            "{} is not a catalogue tool",
            tool.name
        );
        assert!(
            seen.insert(tool.name.to_string()),
            "{} is listed twice",
            tool.name
        );
    }
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted, "tools are listed sorted by name");
    let mut catalogue = CATALOGUE.to_vec();
    catalogue.sort_unstable();
    assert_eq!(
        names, catalogue,
        "the registered tools are exactly the 40 catalogue tools"
    );
    Ok(())
}

#[tokio::test]
async fn every_tool_is_annotated_read_only_with_a_title_and_a_description() -> anyhow::Result<()> {
    let (_h, tools) = tools().await?;
    for tool in &tools {
        let name = &tool.name;
        let annotations = tool
            .annotations
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: no annotations"));
        assert_eq!(
            annotations.read_only_hint,
            Some(true),
            "{name}: readOnlyHint"
        );
        assert_eq!(
            annotations.destructive_hint,
            Some(false),
            "{name}: destructiveHint"
        );
        assert_eq!(
            annotations.idempotent_hint,
            Some(true),
            "{name}: idempotentHint"
        );
        assert_eq!(
            annotations.open_world_hint,
            Some(true),
            "{name}: openWorldHint"
        );
        let title = tool.title.as_deref().unwrap_or_default();
        assert!(title.len() >= 4, "{name}: title");
        assert_eq!(
            annotations.title.as_deref(),
            Some(title),
            "{name}: annotation title"
        );
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.len() >= 40,
            "{name}: description {description:?}"
        );
        assert!(
            !description.contains("\n\n\n") && description == description.trim(),
            "{name}: tidy description"
        );
    }
    Ok(())
}

#[tokio::test]
async fn tools_that_return_names_set_by_others_say_to_treat_them_as_data() -> anyhow::Result<()> {
    // Device names and hostnames come from the devices that join the network, and neighbouring
    // network names from anyone in radio range.
    const UNTRUSTED_NAMES: [&str; 5] = [
        "get_network_scan",
        "list_devices",
        "get_device",
        "list_eero_connections",
        "list_blocked_devices",
    ];
    let (_h, tools) = tools().await?;
    for name in UNTRUSTED_NAMES {
        let tool = tools
            .iter()
            .find(|tool| tool.name == name)
            .unwrap_or_else(|| panic!("{name} is registered"));
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.contains("never as instructions"),
            "{name}: {description}"
        );
        assert!(description.contains("SSIDs"), "{name}: {description}");
    }
    Ok(())
}

#[tokio::test]
async fn every_tool_has_an_output_schema_for_the_shared_output_object() -> anyhow::Result<()> {
    let (_h, tools) = tools().await?;
    for tool in &tools {
        let name = &tool.name;
        let output = tool
            .output_schema
            .as_ref()
            .unwrap_or_else(|| panic!("{name}: no outputSchema"));
        let output = schema_value(output);
        assert_eq!(output["type"], "object", "{name}");
        assert_eq!(
            output["required"],
            json!(["data"]),
            "{name}: only data is required"
        );
        for member in [
            "data",
            "network_id",
            "server_time",
            "window",
            "detail",
            "count",
        ] {
            assert!(
                output["properties"].get(member).is_some(),
                "{name}: {member}"
            );
        }
        walk(&format!("{name}:output"), &output, &mut |path, schema| {
            assert!(!schema.contains_key("default"), "{path}: default keyword");
            assert!(
                !schema.contains_key("format"),
                "{path}: schemars' non-standard integer formats are stripped"
            );
            assert!(
                !schema.get("type").is_some_and(Value::is_array),
                "{path}: type array"
            );
        });
    }
    Ok(())
}

#[tokio::test]
async fn every_input_schema_is_a_portable_closed_object() -> anyhow::Result<()> {
    let (_h, tools) = tools().await?;
    for tool in &tools {
        let name = tool.name.to_string();
        let input = schema_value(&tool.input_schema);
        assert_eq!(input["type"], "object", "{name}: root is an object");
        assert_eq!(
            input["additionalProperties"], false,
            "{name}: unknown fields must be rejected (serde deny_unknown_fields)"
        );
        walk(&format!("{name}:input"), &input, &mut |path, schema| {
            assert!(
                !schema.contains_key("default"),
                "{path}: the default keyword is not portable"
            );
            assert!(
                !schema.get("type").is_some_and(Value::is_array),
                "{path}: type arrays are not portable; publish a single type"
            );
            // schemars adds non-standard integer formats (uint32, int64); a field that only used
            // `drop_default` instead of the matching range transform would leak one.
            assert!(
                !schema.contains_key("format"),
                "{path}: format keywords are not portable; use range_1_100 or positive for integers"
            );
            // Optional fields are plain properties: no null branches either.
            for union in ["anyOf", "oneOf"] {
                if let Some(Value::Array(branches)) = schema.get(union) {
                    assert!(
                        branches
                            .iter()
                            .all(|b| b.get("type") != Some(&json!("null"))),
                        "{path}: {union} with a null branch"
                    );
                }
            }
            // Nested objects are closed too.
            if schema.get("type") == Some(&json!("object")) && schema.contains_key("properties") {
                assert_eq!(
                    schema.get("additionalProperties"),
                    Some(&json!(false)),
                    "{path}: nested objects reject unknown fields"
                );
            }
            // Every property of every object is described.
            if let Some(Value::Object(properties)) = schema.get("properties") {
                for (property, definition) in properties {
                    assert!(
                        definition.get("type").is_some_and(Value::is_string),
                        "{path}: property {property} must publish exactly one string type"
                    );
                    let description = definition
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    assert!(
                        description.len() >= 10,
                        "{path}: property {property} needs a description with its accepted forms and default"
                    );
                    assert!(
                        !description.replace("\n\n", "").contains('\n'),
                        "{path}: property {property}: wrapped lines must be joined"
                    );
                }
            }
        });
    }
    Ok(())
}

#[tokio::test]
async fn id_refresh_and_range_properties_have_the_documented_types() -> anyhow::Result<()> {
    let (_h, tools) = tools().await?;
    for tool in &tools {
        let name = &tool.name;
        let input = schema_value(&tool.input_schema);
        let properties = input["properties"].as_object().cloned().unwrap_or_default();
        for (property, definition) in &properties {
            if property.ends_with("_id") || property == "device_mac" {
                assert_eq!(
                    definition["type"], "string",
                    "{name}.{property}: ids are published as strings (integers are accepted)"
                );
            }
        }
        // refresh is offered by exactly the eight cached tools.
        assert_eq!(
            properties.contains_key("refresh"),
            CACHED.contains(&name.as_ref()),
            "{name}: refresh is offered only by the cached getters"
        );
        if let Some(refresh) = properties.get("refresh") {
            assert_eq!(refresh["type"], "boolean", "{name}");
        }
        for (property, maximum) in [
            ("limit", Some(100)),
            ("page_size", Some(100)),
            ("granularity", Some(4_294_967_295)),
            ("busy_threshold", Some(4_294_967_295)),
        ] {
            if let Some(definition) = properties.get(property) {
                assert_eq!(definition["type"], "integer", "{name}.{property}");
                assert_eq!(definition["minimum"], 1, "{name}.{property}");
                assert_eq!(
                    definition.get("maximum").and_then(Value::as_i64),
                    maximum,
                    "{name}.{property}"
                );
            }
        }
        if let Some(cadence) = properties.get("cadence") {
            assert_eq!(cadence["enum"], json!(["daily", "hourly"]), "{name}");
        }
        for (property, expected) in [
            ("detail", json!(["summary", "full"])),
            (
                "band",
                json!([
                    "band_2_4GHz",
                    "band_5GHz_low",
                    "band_5GHz_high",
                    "band_5GHz_full",
                    "band_6GHz"
                ]),
            ),
        ] {
            if let Some(definition) = properties.get(property) {
                assert_eq!(definition["enum"], expected, "{name}.{property}");
            }
        }
        if let Some(insight) = properties.get("insight_type") {
            assert_eq!(insight["enum"].as_array().map(Vec::len), Some(11), "{name}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn every_tool_rejects_an_unknown_field_before_any_request() -> anyhow::Result<()> {
    let (h, tools) = tools().await?;
    h.expect_no_requests().await;
    for tool in &tools {
        let result = h
            .call(&tool.name, object!({"definitely_not_a_field": 1}))
            .await?;
        assert_eq!(result.is_error, Some(true), "{}", tool.name);
        let text = result.content[0].as_text().expect("text").text.clone();
        assert!(
            text.starts_with("failed to deserialize parameters"),
            "{}: {text}",
            tool.name
        );
    }
    h.assert_no_requests().await;
    Ok(())
}

#[tokio::test]
async fn an_unknown_tool_is_a_protocol_error_not_an_in_band_result() -> anyhow::Result<()> {
    let h = Harness::start().await?;
    let error = h
        .client
        .call_tool(CallToolRequestParams::new("set_dns"))
        .await
        .expect_err("unknown tool");
    assert!(
        matches!(error, ServiceError::McpError(ref data) if data.code == ErrorCode::INVALID_PARAMS),
        "{error:?}"
    );
    Ok(())
}

// ===================== server info =====================

#[tokio::test]
async fn server_info_is_eero_mcp_with_instructions_and_only_the_tools_capability()
-> anyhow::Result<()> {
    let h = Harness::start().await?;
    let info = h.client.peer_info().expect("server info after initialize");

    let server = info.server_info.as_ref().expect("serverInfo");
    assert_eq!(server.name, "eero-mcp", "not rmcp's generated default");
    assert_eq!(server.version, env!("CARGO_PKG_VERSION"));
    assert!(!server.title.as_deref().unwrap_or_default().is_empty());

    let instructions = info.instructions.as_deref().expect("instructions");
    for needle in [
        "Read-only",
        "network_id",
        "list_networks",
        "refresh",
        "eero Plus",
        "authentication_required",
    ] {
        assert!(
            instructions.contains(needle),
            "instructions mention {needle}"
        );
    }

    let capabilities = serde_json::to_value(&info.capabilities)?;
    assert_eq!(
        capabilities,
        json!({"tools": {}}),
        "tools only, no list-changed"
    );

    // rmcp's default client asks for the newest version and ends on the newest with a handshake.
    assert_eq!(info.protocol_version, ProtocolVersion::V_2025_11_25);
    Ok(())
}
