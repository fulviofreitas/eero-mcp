//! The shared call path, driven through its public building blocks (not through a tool), exactly
//! the way a tool handler composes them. These are the executable reference for the groups that
//! have child ids (`device_id`, `profile_id`), extra arguments or time windows:
//!
//! 1. validate every input with [`eero_mcp::ids::Ids`] / [`eero_mcp::window`] / [`eero_mcp::params`]
//!    (no upstream, so no permit is taken for an invalid call);
//! 2. [`eero_mcp::EeroMcp::resolve_network`] (default-network lookup when `network_id` is omitted);
//! 3. finish the child ids' network check ([`eero_mcp::ids::Ids::in_network`]);
//! 4. [`eero_mcp::EeroMcp::read_in`] (or [`eero_mcp::EeroMcp::read_in_for`] when a child id is
//!    forwarded) with a closure that is one `Box::pin(client.read(..))` expression, everything the
//!    read needs travelling through `args`;
//! 5. shape the output with [`eero_mcp::output::ToolOutput`].

mod common;

use common::{authed_get, authed_get_with, direct_server, fixture, json_response};
use eero_mcp::Resolver;
use eero_mcp::ids::NetworkChoice;
use eero_mcp::output::{ToolOutput, WindowEcho};
use eero_mcp::params::{Cadence, IdInput};
use eero_mcp::window::{self, Span};
use wiremock::MockServer;

fn id(value: &str) -> IdInput {
    IdInput::new(value)
}

async fn targets(mock: &MockServer) -> Vec<String> {
    mock.received_requests()
        .await
        .unwrap_or_default()
        .iter()
        .map(|request| match request.url.query() {
            Some(query) => format!("{} {}?{query}", request.method, request.url.path()),
            None => format!("{} {}", request.method, request.url.path()),
        })
        .collect()
}

#[tokio::test]
async fn a_child_id_read_passes_owned_validated_args_to_the_closure() -> anyhow::Result<()> {
    let (mock, server) = direct_server(Resolver::fixed(None)).await?;
    authed_get("/2.2/networks/network-0001/devices/device-0001")
        .respond_with(json_response(&fixture("account", "guest_network")))
        .expect(1)
        .mount(&mock)
        .await;

    // 1. validate, without touching upstream.
    let ids = server.ids();
    let choice = ids.network(Some(&id("network-0001")))?;
    let child = ids.device(&id("  device-0001 "))?;
    // 2. resolve the network (explicit here: no request).
    let network = server.resolve_network(choice).await?;
    // 3. finish the child's network check.
    let device = ids.in_network(&child, &network)?;
    // 4. read; `read_in_for` reports a rusteero id-field error against the child's parameter.
    //    refresh (Copy) is captured; the device (owned) travels through args.
    let refresh = false;
    let envelope = server
        .read_in_for(
            child.param(),
            &network,
            &device,
            move |client, net, device| Box::pin(client.get_device(device, Some(net), refresh)),
        )
        .await?;
    // 5. shape.
    let out = ToolOutput::from_envelope(&envelope).with_network(network);

    assert_eq!(out.network_id(), Some("network-0001"));
    assert_eq!(
        targets(&mock).await,
        ["GET /2.2/networks/network-0001/devices/device-0001"]
    );
    Ok(())
}

#[tokio::test]
async fn a_child_path_is_checked_against_the_default_network_between_the_two_permits()
-> anyhow::Result<()> {
    let (mock, server) = direct_server(Resolver::fixed(None)).await?;
    authed_get("/2.2/networks")
        .respond_with(json_response(&fixture("account", "networks_one")))
        .expect(1)
        .mount(&mock)
        .await;

    let ids = server.ids();
    // Phase one needs no network: the path is well formed and in the profiles family.
    let own = ids.profile(&id("/2.2/networks/network-0001/profiles/profile-0001"))?;
    let other = ids.profile(&id("/2.2/networks/network-0009/profiles/profile-0001"))?;
    assert!(own.needs_network_check() && other.needs_network_check());

    // The default network is resolved once (one cached list read) ...
    let network = server.resolve_network(NetworkChoice::Default).await?;
    assert_eq!(network, "network-0001");
    // ... then the path must name that network, still before any read of the profile.
    assert_eq!(ids.in_network(&own, &network)?, "profile-0001");
    let error = ids
        .in_network(&other, &network)
        .expect_err("another network's profile");
    assert_eq!(error.code.as_str(), "invalid_argument");
    assert_eq!(error.field.as_deref(), Some("profile_id"));
    assert!(
        !error.message.contains("network-0009"),
        "never echoes input"
    );

    assert_eq!(targets(&mock).await, ["GET /2.2/networks"]);
    Ok(())
}

/// A windowed tool, composed exactly as the pattern in `eero_mcp::tools` shows it: validate the
/// window and the enumerations first, resolve the network, read through `args`, echo the window.
async fn windowed_tool(
    server: &eero_mcp::EeroMcp,
    timezone: Option<String>,
) -> anyhow::Result<ToolOutput> {
    let choice = server.ids().network(Some(&id("network-0001")))?;
    let window = window::resolve(
        Some("2026-10-16T00:00:00Z"),
        Some("2026-10-23T00:00:00Z"),
        Span::Days7,
    )?;
    let cadence = Cadence::Hourly;
    let network = server.resolve_network(choice).await?;
    let envelope = server
        .read_in(
            &network,
            &(window.clone(), cadence, timezone.clone()),
            |c, net, (window, cadence, timezone)| {
                Box::pin(c.get_data_usage(
                    &window.start,
                    &window.end,
                    cadence.as_str(),
                    timezone.as_deref(),
                    None,
                    Some(net),
                ))
            },
        )
        .await?;
    let echo = WindowEcho::new(window)
        .cadence(cadence)
        .timezone(timezone.as_deref());
    Ok(ToolOutput::from_envelope(&envelope)
        .with_network(network)
        .with_window(echo))
}

#[tokio::test]
async fn a_windowed_read_sends_the_effective_window_and_echoes_it() -> anyhow::Result<()> {
    let (mock, server) = direct_server(Resolver::fixed(None)).await?;
    // The query is pinned exactly: no `timezone` (it was omitted) and nothing else.
    authed_get_with(
        "/2.2/networks/network-0001/data_usage",
        &[
            ("start", "2026-10-16T00:00:00Z"),
            ("end", "2026-10-23T00:00:00Z"),
            ("cadence", "hourly"),
        ],
    )
    .respond_with(json_response(&fixture("account", "guest_network")))
    .expect(1)
    .mount(&mock)
    .await;

    let out = windowed_tool(&server, None).await?;

    let value = serde_json::to_value(&out)?;
    assert_eq!(
        value["window"],
        serde_json::json!({
            "start": "2026-10-16T00:00:00Z",
            "end": "2026-10-23T00:00:00Z",
            "cadence": "hourly"
        })
    );
    assert_eq!(targets(&mock).await.len(), 1);
    Ok(())
}

#[tokio::test]
async fn a_given_timezone_is_passed_through_and_echoed() -> anyhow::Result<()> {
    let (mock, server) = direct_server(Resolver::fixed(None)).await?;
    authed_get_with(
        "/2.2/networks/network-0001/data_usage",
        &[
            ("start", "2026-10-16T00:00:00Z"),
            ("end", "2026-10-23T00:00:00Z"),
            ("cadence", "hourly"),
            ("timezone", "America/Los_Angeles"),
        ],
    )
    .respond_with(json_response(&fixture("account", "guest_network")))
    .expect(1)
    .mount(&mock)
    .await;

    let out = windowed_tool(&server, Some("America/Los_Angeles".to_owned())).await?;

    let window = serde_json::to_value(&out)?["window"].clone();
    assert_eq!(window["timezone"], "America/Los_Angeles");
    assert_eq!(window["cadence"], "hourly");
    Ok(())
}

#[tokio::test]
async fn account_level_reads_need_no_network() -> anyhow::Result<()> {
    let (mock, server) = direct_server(Resolver::fixed(None)).await?;
    authed_get("/2.2/account")
        .respond_with(json_response(&fixture("account", "account")))
        .expect(1)
        .mount(&mock)
        .await;

    let envelope = server
        .read(|client| Box::pin(client.get_account(false)))
        .await?;

    assert_eq!(envelope.data()["id"], "user-0001");
    Ok(())
}

#[tokio::test]
async fn errors_from_a_read_closure_are_mapped_by_the_call_path() -> anyhow::Result<()> {
    let (mock, server) = direct_server(Resolver::fixed(None)).await?;
    authed_get("/2.2/networks/network-0001/devices/device-0001")
        .respond_with(wiremock::ResponseTemplate::new(404))
        .expect(1)
        .mount(&mock)
        .await;

    let error = server
        .read_in("network-0001", &"device-0001", |client, net, device| {
            Box::pin(client.get_device(device, Some(net), false))
        })
        .await
        .expect_err("404");

    assert_eq!(error.code.as_str(), "not_found");
    assert_eq!(error.upstream_status, Some(404));
    Ok(())
}

#[tokio::test]
async fn an_id_validation_error_raised_inside_a_read_names_the_forwarded_parameter()
-> anyhow::Result<()> {
    // The tools validate ids before the read, so rusteero's own id validation should never fire.
    // If it ever does (an id that slips through), the error still names the parameter the read
    // forwarded instead of dropping it. An empty device id is refused by rusteero before any
    // request, which provokes exactly that.
    let (_mock, server) = direct_server(Resolver::fixed(None)).await?;

    let error = server
        .read_in_for("device_id", "network-0001", &"", |client, net, device| {
            Box::pin(client.get_device(device, Some(net), false))
        })
        .await
        .expect_err("rusteero refuses an empty device id");
    assert_eq!(error.code.as_str(), "invalid_argument");
    assert_eq!(error.field.as_deref(), Some("device_id"));
    assert!(error.upstream_status.is_none(), "a local error");

    // `read_in` reports against the network id.
    let error = server
        .read_in("network-0001", &"", |client, net, device| {
            Box::pin(client.get_device(device, Some(net), false))
        })
        .await
        .expect_err("rusteero refuses an empty device id");
    assert_eq!(error.field.as_deref(), Some("network_id"));

    // A read that forwards no id has nothing to name.
    let error = server
        .read(|client| Box::pin(client.get_device("", Some("network-0001"), false)))
        .await
        .expect_err("rusteero refuses an empty device id");
    assert_eq!(error.code.as_str(), "invalid_argument");
    assert_eq!(error.field, None);
    Ok(())
}
