//! The devices group: tools 11 to 14.
//!
//! | # | Tool | rusteero read | Inputs (optional unless marked) |
//! |---|---|---|---|
//! | 11 | `list_devices` | `get_devices` (cached; always unfiltered: both filters are `None`) | `network_id`, `refresh`, `detail` (`summary` default or `full`) |
//! | 12 | `get_device` | `get_device` (cached) | `device_id` (required), `network_id`, `refresh` |
//! | 13 | `list_blocked_devices` | `get_blacklist` | `network_id` |
//! | 14 | `get_transfer_stats` | `get_transfer_stats` | `network_id`, `device_id` (optional; omitted means network-wide) |
//!
//! `list_devices` projects each device with [`crate::output::summarize_devices`] unless `detail`
//! is `full`, which returns the raw device array (unwrapped from eero's container when the list
//! arrives wrapped), redacted. When the data has no recognisable device list, the raw (redacted)
//! data is returned whatever the mode, `detail` reports `full` (what `data` actually holds) and
//! `count` is not meaningful.
//!
//! A `device_id` is validated with [`crate::ids::Ids::device`] before anything else, and a path or
//! URL form is checked against the addressed network with [`crate::ids::Ids::in_network`] once
//! that network is known. An empty `device_id` is rejected rather than forwarded: rusteero treats
//! an empty device id for the transfer read as absent, which would silently answer network-wide.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{Json, tool, tool_router};
use rusteero::Envelope;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

use crate::errors::ToolError;
use crate::ids::ChildId;
use crate::output::{ToolOutput, device_list, summarize_devices};
use crate::params::{DetailMode, IdInput, NetworkParams, drop_default};
use crate::server::EeroMcp;

/// Input of `list_devices`.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListDevicesParams {
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
    /// Set true to bypass the 60-second cache and fetch fresh data (the fresh response is cached
    /// again). Defaults to false.
    #[serde(default)]
    #[schemars(with = "bool", transform = drop_default)]
    pub refresh: Option<bool>,
    /// How much of each device to return: summary or full. summary keeps the fields that answer
    /// most questions (names, MAC, IP, connection, the eero and profile it belongs to, block and
    /// pause state) and keeps the answer small; full returns every field eero sends. Defaults to
    /// summary.
    #[serde(default)]
    #[schemars(with = "DetailMode", transform = drop_default)]
    pub detail: Option<DetailMode>,
}

/// Input of `get_device`.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceParams {
    /// Device to read (required). Accepts a bare device id, a MAC address in any common spelling,
    /// or an API path or absolute URL under the same network's devices, as a string or an
    /// integer. list_devices shows each device's url and mac.
    pub device_id: IdInput,
    /// Network the device is on. Accepts a bare network id, an API path such as
    /// /2.2/networks/ID, or an absolute URL on the eero API origin, as a string or an integer. Omit
    /// it to use the account's only network; with several networks the call fails and lists their
    /// ids (call list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
    /// Set true to bypass the 60-second cache and fetch fresh data (the fresh response is cached
    /// again). Defaults to false.
    #[serde(default)]
    #[schemars(with = "bool", transform = drop_default)]
    pub refresh: Option<bool>,
}

/// Input of `get_transfer_stats`.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TransferStatsParams {
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
    /// Device to read transfer statistics for. Accepts a bare device id, a MAC address in any
    /// common spelling, or an API path or absolute URL under the same network's devices, as a
    /// string or an integer. Omit it for the network-wide statistics.
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub device_id: Option<IdInput>,
}

/// The `list_devices` output: the projected list in summary mode, the raw device array in full
/// mode.
///
/// Both modes return an array, whichever container eero wrapped the list in. Data without a
/// recognisable device list falls back to the raw data and reports `full`, so `detail` always
/// names what `data` holds. `count` is then 0 (the number of devices recognised): the output type
/// cannot omit it, so the tool description tells agents it is not meaningful in that case.
fn device_list_output(envelope: &Envelope, detail: DetailMode) -> ToolOutput {
    if detail == DetailMode::Summary
        && let Some(devices) = summarize_devices(envelope.data())
    {
        let count = devices.len();
        return ToolOutput::from_envelope_with_data(envelope, &Value::Array(devices))
            .with_detail(DetailMode::Summary, count);
    }
    if let Some(list) = device_list(envelope.data()) {
        return ToolOutput::from_envelope_with_data(envelope, &Value::Array(list.clone()))
            .with_detail(DetailMode::Full, list.len());
    }
    ToolOutput::from_envelope(envelope).with_detail(DetailMode::Full, 0)
}

#[tool_router(router = devices_router, vis = "pub(crate)")]
impl EeroMcp {
    #[tool(
        title = "List devices",
        description = concat!(
            "List the devices known to a network, online or not: by default each device is ",
            "trimmed to its id, url, MAC, names, manufacturer, device type and model name, IP ",
            "addresses, connection (connected, wireless or wired, band), the eero it is ",
            "attached to, its profile, its blocked, paused, prioritized and guest state, and ",
            "when it was first and last active; set detail to full for every field eero sends. ",
            "The result carries detail and count (the number of devices). If data is not an ",
            "array, eero sent an unexpected shape and count is not meaningful. Use it to find ",
            "a device_id for get_device. network_id defaults to the account's only network. ",
            "Cached for 60 seconds; set refresh to bypass the cache. Secret values are redacted."
        ),
        annotations(
            title = "List devices",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn list_devices(
        &self,
        Parameters(p): Parameters<ListDevicesParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let refresh = p.refresh.unwrap_or(false);
        let detail = p.detail.unwrap_or_default();
        let choice = self.ids().network(p.network_id.as_ref())?;
        let network = self.resolve_network(choice).await?;
        let envelope = self
            .read_in(&network, &(), move |c, net, ()| {
                // Both filters stay unset, so the read is cached.
                Box::pin(c.get_devices(Some(net), refresh, None, None))
            })
            .await?;
        Ok(Json(
            device_list_output(&envelope, detail).with_network(network),
        ))
    }

    #[tool(
        title = "Get device",
        description = concat!(
            "Get one device in full: names, MAC, manufacturer, device type, IP addresses, ",
            "connection details, the eero and profile it belongs to, and its block, pause and ",
            "guest state, exactly as eero reports them. device_id is required: a bare id, a MAC ",
            "address in any common spelling (the one list_devices shows is the safe choice), or ",
            "an API path or absolute URL under the same network's devices. network_id defaults ",
            "to the account's only network. Cached for 60 seconds; set refresh to bypass the ",
            "cache. Secret values are redacted."
        ),
        annotations(
            title = "Get device",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_device(
        &self,
        Parameters(p): Parameters<DeviceParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let ids = self.ids();
        let choice = ids.network(p.network_id.as_ref())?;
        let child = ids.device(&p.device_id)?;
        let network = self.resolve_network(choice).await?;
        let device = ids.in_network(&child, &network)?;
        let refresh = p.refresh.unwrap_or(false);
        let envelope = self
            .read_in_for(child.param(), &network, &device, move |c, net, device| {
                Box::pin(c.get_device(device, Some(net), refresh))
            })
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope).with_network(network),
        ))
    }

    #[tool(
        title = "List blocked devices",
        description = concat!(
            "List the devices on a network's block list (devices kept off the network), exactly ",
            "as eero reports the entries. list_devices shows the same devices with their names ",
            "and a blocked flag. network_id defaults to the account's only network. Secret ",
            "values are redacted."
        ),
        annotations(
            title = "List blocked devices",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn list_blocked_devices(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_blacklist(Some(net)))
        })
        .await
    }

    #[tool(
        title = "Get transfer stats",
        description = concat!(
            "Get data transfer statistics for a network, or for one device when device_id is ",
            "given (a bare id, a MAC address, or an API path or absolute URL under the same ",
            "network's devices); omit device_id for the network-wide figures. Some accounts get ",
            "a 403 from eero for this read: access_denied when eero says the account lacks ",
            "permission, premium_required when eero points to a missing subscription, and ",
            "otherwise upstream_error with upstream_status 403. network_id defaults to the ",
            "account's only network. Secret values are redacted."
        ),
        annotations(
            title = "Get transfer stats",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_transfer_stats(
        &self,
        Parameters(p): Parameters<TransferStatsParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let ids = self.ids();
        let choice = ids.network(p.network_id.as_ref())?;
        let child = p
            .device_id
            .as_ref()
            .map(|device| ids.device(device))
            .transpose()?;
        let network = self.resolve_network(choice).await?;
        let device = child
            .as_ref()
            .map(|child| ids.in_network(child, &network))
            .transpose()?;
        let id_param = child.as_ref().map_or("network_id", ChildId::param);
        let envelope = self
            .read_in_for(id_param, &network, &device, |c, net, device| {
                Box::pin(c.get_transfer_stats(Some(net), device.as_deref()))
            })
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope).with_network(network),
        ))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn envelope(data: &Value) -> Envelope {
        Envelope::from_value(json!({"meta": {"code": 200}, "data": data}))
    }

    fn device(n: u32) -> Value {
        json!({
            "url": format!("/2.2/networks/network-0001/devices/device-000{n}"),
            "mac": format!("aa:bb:cc:00:00:0{n}"),
            "hostname": "example-host",
            "unlisted": "dropped"
        })
    }

    #[test]
    fn summary_projects_a_bare_array_and_counts_it() {
        let out = device_list_output(
            &envelope(&json!([device(1), device(2)])),
            DetailMode::Summary,
        );
        assert_eq!(out.detail(), Some(DetailMode::Summary));
        assert_eq!(out.count(), Some(2));
        assert_eq!(out.data()[0]["id"], "device-0001");
        assert!(out.data()[0].get("unlisted").is_none());
    }

    #[test]
    fn summary_projects_a_wrapped_list_and_an_empty_one() {
        for (data, count) in [
            (json!({"devices": [device(1)]}), 1_usize),
            (json!({"data": [device(1), device(2), device(3)]}), 3),
            (json!([]), 0),
            (json!({"devices": []}), 0),
        ] {
            let out = device_list_output(&envelope(&data), DetailMode::Summary);
            assert_eq!(out.detail(), Some(DetailMode::Summary), "{data}");
            assert_eq!(out.count(), u64::try_from(count).ok(), "{data}");
            assert_eq!(out.data().as_array().map(Vec::len), Some(count));
        }
    }

    #[test]
    fn full_returns_the_raw_device_array_whatever_its_container() {
        let list = json!([device(1)]);
        for data in [
            list.clone(),
            json!({"devices": [device(1)], "total": 1}),
            json!({"data": [device(1)]}),
        ] {
            let out = device_list_output(&envelope(&data), DetailMode::Full);
            assert_eq!(out.detail(), Some(DetailMode::Full), "{data}");
            assert_eq!(out.count(), Some(1), "{data}");
            assert_eq!(out.data(), &list, "{data}");
        }
    }

    #[test]
    fn a_summary_over_an_unrecognised_shape_falls_back_to_the_raw_data() {
        for data in [json!({"unexpected": true}), Value::Null, json!("text")] {
            for detail in [DetailMode::Summary, DetailMode::Full] {
                let out = device_list_output(&envelope(&data), detail);
                assert_eq!(out.detail(), Some(DetailMode::Full), "{data}");
                assert_eq!(out.count(), Some(0), "{data}");
                assert_eq!(out.data(), &data);
            }
        }
    }

    #[test]
    fn both_modes_redact() {
        let data = json!([{"url": "/2.2/networks/network-0001/devices/device-0001", "password": "devicepass000"}]);
        let full = device_list_output(&envelope(&data), DetailMode::Full);
        assert_eq!(full.data()[0]["password"], "[REDACTED]");
        let raw = device_list_output(
            &envelope(&json!({"password": "devicepass000"})),
            DetailMode::Summary,
        );
        assert_eq!(raw.data()["password"], "[REDACTED]");
    }
}
