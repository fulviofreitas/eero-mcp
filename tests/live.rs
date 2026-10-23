//! Live, human-run reads against the real eero cloud API. Never run in CI.
//!
//! - Every live test is `#[ignore]`d **and** gated at run time on `EERO_MCP_LIVE=1`, so neither a
//!   plain `cargo test` nor an `--ignored` run without the variable touches the network.
//! - The tools to call are a hand-written allowlist ([`LIVE_READS`]); nothing is derived from the
//!   registered tool list, so no future tool can be swept in by accident.
//! - Credentials come from the normal read-only resolution chain (the environment, the OS keyring,
//!   a credential file), exactly as the binary resolves them.
//! - Output is limited to result codes, sorted top-level key names and counts: never a body, never
//!   an identifier. A failure is reported by its error code only, and a 200 is not asserted
//!   (accounts without eero Plus legitimately get errors).
//!
//! ```text
//! EERO_MCP_LIVE=1 cargo test --all-features --test live -- --ignored --nocapture
//! ```

mod common;

use eero_mcp::config::{EnvMap, Settings};
use eero_mcp::credentials::{CredentialChain, Resolver, resolve_at_startup};
use eero_mcp::{EeroMcp, client_builder};
use rmcp::ServiceExt as _;
use rmcp::model::CallToolRequestParams;
use rmcp::object;
use serde_json::Value;
use std::sync::Arc;

/// The tools a live run calls, each with no arguments. Add a tool here by hand when its group
/// lands. Network-scoped tools use the account's only network; on an account with several networks they
/// report `invalid_argument`, which is also a legitimate outcome to look at.
const LIVE_READS: &[&str] = &[
    "get_account",
    "list_networks",
    "get_network",
    "get_guest_network",
    "list_network_members",
    "get_network_permissions",
    "get_premium_features",
    "list_eeros",
    "list_devices",
    "list_blocked_devices",
    "get_transfer_stats",
    "list_speed_tests",
    "get_diagnostics",
    "get_firmware_updates",
    "get_channel_utilization",
    "get_network_scan",
    "list_activity_events",
    "list_notifications",
    "list_profiles",
    "list_port_forwards",
    "list_dhcp_reservations",
    "get_subnets",
    "get_wpa3_settings",
    "get_fast_transition",
    "get_content_filter",
    "get_backup_internet",
];

fn live_enabled() -> bool {
    std::env::var("EERO_MCP_LIVE").is_ok_and(|value| value == "1")
}

/// What may be printed about a result: no body, no identifier.
fn describe(result: &rmcp::model::CallToolResult) -> String {
    if result.is_error == Some(true) {
        let code = common::error_json(result)
            .ok()
            .and_then(|value| value["error"]["code"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "unrecognised".to_owned());
        return format!("error code={code}");
    }
    let Ok(value) = common::structured(result) else {
        return "ok (unparsable result)".to_owned();
    };
    match &value["data"] {
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            format!("ok keys={keys:?}")
        }
        Value::Array(items) => format!("ok count={}", items.len()),
        Value::Null => "ok data=null".to_owned(),
        _ => "ok data=scalar".to_owned(),
    }
}

#[tokio::test]
#[ignore = "live: reads the real eero cloud; set EERO_MCP_LIVE=1 and pass --ignored"]
async fn live_read_only_sweep() -> anyhow::Result<()> {
    if !live_enabled() {
        println!("EERO_MCP_LIVE is not 1: skipping the live sweep");
        return Ok(());
    }

    let settings = Settings::from_env(&EnvMap::from_process())?;
    let chain = Arc::new(CredentialChain::from_settings(&settings));
    let token = resolve_at_startup(Arc::clone(&chain)).await?;
    println!("credential found: {}", token.is_some());
    let client = client_builder(settings.api_base_url.as_deref(), token.as_ref())
        .build()
        .await?;
    let server = EeroMcp::new(client, Resolver::new(chain));

    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let running = server.serve(server_io).await?;
        running.waiting().await?;
        anyhow::Ok(())
    });
    let client = ().serve(client_io).await?;

    for tool in LIVE_READS {
        let result = client
            .call_tool(CallToolRequestParams::new(*tool).with_arguments(object!({})))
            .await?;
        println!("{tool}: {}", describe(&result));
    }
    Ok(())
}

/// Runs in every `cargo test`: the allowlist names real tools, so a rename cannot leave a stale
/// entry that a live run would only discover by failing.
#[tokio::test]
async fn the_live_allowlist_names_only_registered_tools() -> anyhow::Result<()> {
    let h = common::Harness::start().await?;
    let registered: Vec<String> = h
        .client
        .list_all_tools()
        .await?
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    for tool in LIVE_READS {
        assert!(
            registered.iter().any(|name| name == tool),
            "{tool} is not registered"
        );
    }
    let mut sorted = LIVE_READS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), LIVE_READS.len(), "no duplicates");
    Ok(())
}
