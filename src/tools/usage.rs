//! The usage group: tools 33 to 40.
//!
//! All eight are time-windowed (default last 7 days, `cadence` daily) and echo the effective
//! window with [`crate::output::WindowEcho`].
//!
//! | # | Tool | rusteero read | Inputs (optional unless marked) |
//! |---|---|---|---|
//! | 33 | `get_data_usage` | `get_data_usage` | `network_id`, `start`, `end`, `cadence`, `timezone` |
//! | 34 | `get_devices_data_usage` | `get_devices_data_usage` (always passes a cadence, default daily) | `network_id`, `start`, `end`, `cadence`, `timezone`, `profile_id` |
//! | 35 | `get_device_data_usage` | `get_device_data_usage` | `device_mac` (required), `network_id`, `start`, `end`, `cadence`, `timezone` |
//! | 36 | `get_eeros_data_usage` | `get_eeros_data_usage` | `network_id`, `start`, `end`, `cadence`, `timezone` |
//! | 37 | `get_profile_data_usage` | `get_profile_data_usage` | `profile_id` (required), `network_id`, `start`, `end`, `cadence`, `timezone` |
//! | 38 | `get_insights` | `get_insights` (likely eero Plus or Secure; this read takes `insight_type` before `cadence`) | `network_id`, `start`, `end`, `cadence`, `insight_type` |
//! | 39 | `get_devices_insights` | `get_devices_insights` | `network_id`, `start`, `end`, `cadence`, `insight_type` |
//! | 40 | `get_device_insights` | `get_device_insights` | `device_id` (required), `network_id`, `start`, `end`, `cadence`, `insight_type` |
//!
//! Tools 33 to 37 take rusteero's optional per-call timeout: it is always left unset, so the
//! default timeouts apply. None of the eight is cached, so none offers `refresh`.
//!
//! Every handler validates without touching upstream first (ids, the window, the enumerations),
//! then resolves the network, then finishes the network check of a profile or device path, then
//! reads. A window is resolved with [`crate::window::resolve`] and `Span::Days7`: both bounds
//! omitted is the last 7 days ending now, one bound derives the other, `start` must be strictly
//! before `end`. Follow [`super::account`] for the rest of the pattern.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{Json, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::errors::ToolError;
use crate::ids;
use crate::output::{ToolOutput, WindowEcho};
use crate::params::{Cadence, IdInput, InsightType, drop_default};
use crate::server::EeroMcp;
use crate::window::{self, Span, Window};

/// The validated window, bucket size and time zone of a data-usage tool.
#[derive(Debug, Clone)]
struct UsageWindow {
    window: Window,
    cadence: Cadence,
    timezone: Option<String>,
}

impl UsageWindow {
    /// Resolves the window (7-day default) and applies the cadence default; no upstream call.
    fn new(
        start: Option<&str>,
        end: Option<&str>,
        cadence: Option<Cadence>,
        timezone: Option<String>,
    ) -> Result<Self, ToolError> {
        Ok(Self {
            window: window::resolve(start, end, Span::Days7)?,
            cadence: cadence.unwrap_or_default(),
            timezone,
        })
    }

    /// The `window` member of the output.
    fn echo(&self) -> WindowEcho {
        WindowEcho::new(self.window.clone())
            .cadence(self.cadence)
            .timezone(self.timezone.as_deref())
    }
}

/// The validated window, bucket size and insight category of an insights tool.
#[derive(Debug, Clone)]
struct InsightWindow {
    window: Window,
    cadence: Cadence,
    insight_type: InsightType,
}

impl InsightWindow {
    /// Resolves the window (7-day default) and applies the cadence and insight type defaults; no
    /// upstream call.
    fn new(
        start: Option<&str>,
        end: Option<&str>,
        cadence: Option<Cadence>,
        insight_type: Option<InsightType>,
    ) -> Result<Self, ToolError> {
        Ok(Self {
            window: window::resolve(start, end, Span::Days7)?,
            cadence: cadence.unwrap_or_default(),
            insight_type: insight_type.unwrap_or_default(),
        })
    }

    /// The `window` member of the output.
    fn echo(&self) -> WindowEcho {
        WindowEcho::new(self.window.clone())
            .cadence(self.cadence)
            .insight_type(self.insight_type)
    }
}

/// Input of get_data_usage and get_eeros_data_usage.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsageParams {
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
    /// Start of the window as an RFC 3339 timestamp, for example 2026-10-16T00:00:00Z. Defaults to
    /// 7 days before end; with both start and end omitted the window is the last 7 days ending
    /// now.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub start: Option<String>,
    /// End of the window as an RFC 3339 timestamp, for example 2026-10-23T00:00:00Z. Must be
    /// after start. Defaults to 7 days after start, or now when start is omitted too.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub end: Option<String>,
    /// Bucket size: daily or hourly. Defaults to daily.
    #[serde(default)]
    #[schemars(with = "Cadence", transform = drop_default)]
    pub cadence: Option<Cadence>,
    /// IANA time zone name, such as America/Los_Angeles, passed to eero unchanged. Omit it to
    /// let eero use its default.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub timezone: Option<String>,
}

/// Input of get_devices_data_usage.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DevicesUsageParams {
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
    /// Start of the window as an RFC 3339 timestamp, for example 2026-10-16T00:00:00Z. Defaults to
    /// 7 days before end; with both start and end omitted the window is the last 7 days ending
    /// now.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub start: Option<String>,
    /// End of the window as an RFC 3339 timestamp, for example 2026-10-23T00:00:00Z. Must be
    /// after start. Defaults to 7 days after start, or now when start is omitted too.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub end: Option<String>,
    /// Bucket size: daily or hourly. Defaults to daily.
    #[serde(default)]
    #[schemars(with = "Cadence", transform = drop_default)]
    pub cadence: Option<Cadence>,
    /// IANA time zone name, such as America/Los_Angeles, passed to eero unchanged. Omit it to
    /// let eero use its default.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub timezone: Option<String>,
    /// Only count the devices of this profile. Accepts a bare profile id, or an API path or URL
    /// under the same network's profiles, as a string or an integer. Omit it for every device
    /// (call list_profiles to find profile ids).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub profile_id: Option<IdInput>,
}

/// Input of get_device_data_usage.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceUsageParams {
    /// MAC address of the device (required), written as list_devices shows it, for example
    /// aa:bb:cc:00:00:01.
    pub device_mac: IdInput,
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
    /// Start of the window as an RFC 3339 timestamp, for example 2026-10-16T00:00:00Z. Defaults to
    /// 7 days before end; with both start and end omitted the window is the last 7 days ending
    /// now.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub start: Option<String>,
    /// End of the window as an RFC 3339 timestamp, for example 2026-10-23T00:00:00Z. Must be
    /// after start. Defaults to 7 days after start, or now when start is omitted too.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub end: Option<String>,
    /// Bucket size: daily or hourly. Defaults to daily.
    #[serde(default)]
    #[schemars(with = "Cadence", transform = drop_default)]
    pub cadence: Option<Cadence>,
    /// IANA time zone name, such as America/Los_Angeles, passed to eero unchanged. Omit it to
    /// let eero use its default.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub timezone: Option<String>,
}

/// Input of get_profile_data_usage.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileUsageParams {
    /// Profile to read (required). Accepts a bare profile id, or an API path or URL under the
    /// same network's profiles, as a string or an integer (call list_profiles to find ids).
    pub profile_id: IdInput,
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
    /// Start of the window as an RFC 3339 timestamp, for example 2026-10-16T00:00:00Z. Defaults to
    /// 7 days before end; with both start and end omitted the window is the last 7 days ending
    /// now.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub start: Option<String>,
    /// End of the window as an RFC 3339 timestamp, for example 2026-10-23T00:00:00Z. Must be
    /// after start. Defaults to 7 days after start, or now when start is omitted too.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub end: Option<String>,
    /// Bucket size: daily or hourly. Defaults to daily.
    #[serde(default)]
    #[schemars(with = "Cadence", transform = drop_default)]
    pub cadence: Option<Cadence>,
    /// IANA time zone name, such as America/Los_Angeles, passed to eero unchanged. Omit it to
    /// let eero use its default.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub timezone: Option<String>,
}

/// Input of get_insights and get_devices_insights.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InsightsParams {
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
    /// Start of the window as an RFC 3339 timestamp, for example 2026-10-16T00:00:00Z. Defaults to
    /// 7 days before end; with both start and end omitted the window is the last 7 days ending
    /// now.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub start: Option<String>,
    /// End of the window as an RFC 3339 timestamp, for example 2026-10-23T00:00:00Z. Must be
    /// after start. Defaults to 7 days after start, or now when start is omitted too.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub end: Option<String>,
    /// Bucket size: daily or hourly. Defaults to daily.
    #[serde(default)]
    #[schemars(with = "Cadence", transform = drop_default)]
    pub cadence: Option<Cadence>,
    /// Insight category to report, for example blocked, adblock, malware or inspected. Defaults
    /// to blocked.
    #[serde(default)]
    #[schemars(with = "InsightType", transform = drop_default)]
    pub insight_type: Option<InsightType>,
}

/// Input of get_device_insights.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeviceInsightsParams {
    /// Device to read (required). Accepts a bare id, a MAC address in any common spelling, or an
    /// API path or URL under the same network's devices, as a string or an integer (call
    /// list_devices to find devices).
    pub device_id: IdInput,
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
    /// Start of the window as an RFC 3339 timestamp, for example 2026-10-16T00:00:00Z. Defaults to
    /// 7 days before end; with both start and end omitted the window is the last 7 days ending
    /// now.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub start: Option<String>,
    /// End of the window as an RFC 3339 timestamp, for example 2026-10-23T00:00:00Z. Must be
    /// after start. Defaults to 7 days after start, or now when start is omitted too.
    #[serde(default)]
    #[schemars(with = "String", transform = drop_default)]
    pub end: Option<String>,
    /// Bucket size: daily or hourly. Defaults to daily.
    #[serde(default)]
    #[schemars(with = "Cadence", transform = drop_default)]
    pub cadence: Option<Cadence>,
    /// Insight category to report, for example blocked, adblock, malware or inspected. Defaults
    /// to blocked.
    #[serde(default)]
    #[schemars(with = "InsightType", transform = drop_default)]
    pub insight_type: Option<InsightType>,
}

#[tool_router(router = usage_router, vis = "pub(crate)")]
impl EeroMcp {
    #[tool(
        title = "Get data usage",
        description = concat!(
            "Get the network's total data usage over a time window: upload and download byte ",
            "totals as eero's time series, bucketed daily or hourly. Use it for questions such ",
            "as how much data the network used this week. start and end are RFC 3339 ",
            "timestamps and default to the last 7 days ending now (give one bound and the ",
            "other is derived 7 days away); cadence defaults to daily; timezone is an optional ",
            "IANA name passed to eero unchanged. The effective window is echoed in the window ",
            "member. network_id defaults to the account's only network. Not cached. If eero ",
            "refuses the report for the account's plan the call fails with premium_required."
        ),
        annotations(
            title = "Get data usage",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_data_usage(
        &self,
        Parameters(p): Parameters<UsageParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let choice = self.ids().network(p.network_id.as_ref())?;
        let query = UsageWindow::new(p.start.as_deref(), p.end.as_deref(), p.cadence, p.timezone)?;
        let network = self.resolve_network(choice).await?;
        let envelope = self
            .read_in(&network, &query, |c, net, q| {
                Box::pin(c.get_data_usage(
                    &q.window.start,
                    &q.window.end,
                    q.cadence.as_str(),
                    q.timezone.as_deref(),
                    None,
                    Some(net),
                ))
            })
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope)
                .with_network(network)
                .with_window(query.echo()),
        ))
    }

    #[tool(
        title = "Get data usage per device",
        description = concat!(
            "Get data usage for every device on the network over a time window (download and ",
            "upload bytes per device), to rank which devices used the most data. Optionally ",
            "limit it to the devices of one household profile with profile_id. start and end ",
            "are RFC 3339 timestamps and default to the last 7 days ending now (give one bound ",
            "and the other is derived 7 days away); cadence defaults to daily; timezone is an ",
            "optional IANA name passed to eero unchanged. The effective window is echoed in the ",
            "window member. network_id defaults to the account's only network. Not cached. If ",
            "eero refuses the report for the account's plan the call fails with premium_required."
        ),
        annotations(
            title = "Get data usage per device",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_devices_data_usage(
        &self,
        Parameters(p): Parameters<DevicesUsageParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let ids = self.ids();
        let choice = ids.network(p.network_id.as_ref())?;
        let profile = p
            .profile_id
            .as_ref()
            .map(|id| ids.profile(id))
            .transpose()?;
        let query = UsageWindow::new(p.start.as_deref(), p.end.as_deref(), p.cadence, p.timezone)?;
        let network = self.resolve_network(choice).await?;
        let profile = profile
            .map(|child| ids.in_network(&child, &network))
            .transpose()?;
        // rusteero forwards the profile filter unchecked: the only id it validates inside this
        // read is the network's, so `read_in` (reporting against network_id) is the right call.
        let envelope = self
            .read_in(
                &network,
                &(query.clone(), profile),
                |c, net, (q, profile)| {
                    Box::pin(c.get_devices_data_usage(
                        &q.window.start,
                        &q.window.end,
                        Some(q.cadence.as_str()),
                        q.timezone.as_deref(),
                        profile.as_deref(),
                        None,
                        Some(net),
                    ))
                },
            )
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope)
                .with_network(network)
                .with_window(query.echo()),
        ))
    }

    #[tool(
        title = "Get device data usage",
        description = concat!(
            "Get one device's data usage over a time window: its upload and download byte ",
            "series, bucketed daily or hourly. device_mac is required: the MAC address as ",
            "list_devices shows it. start and end are RFC 3339 timestamps and default to the ",
            "last 7 days ending now (give one bound and the other is derived 7 days away); ",
            "cadence defaults to daily; timezone is an optional IANA name passed to eero ",
            "unchanged. The effective window is echoed in the window member. network_id ",
            "defaults to the account's only network. Not cached. If eero refuses the report for ",
            "the account's plan the call fails with premium_required."
        ),
        annotations(
            title = "Get device data usage",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_device_data_usage(
        &self,
        Parameters(p): Parameters<DeviceUsageParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let choice = self.ids().network(p.network_id.as_ref())?;
        let device_mac = ids::device_mac(&p.device_mac)?;
        let query = UsageWindow::new(p.start.as_deref(), p.end.as_deref(), p.cadence, p.timezone)?;
        let network = self.resolve_network(choice).await?;
        let envelope = self
            .read_in_for(
                "device_mac",
                &network,
                &(query.clone(), device_mac),
                |c, net, (q, device_mac)| {
                    Box::pin(c.get_device_data_usage(
                        device_mac,
                        &q.window.start,
                        &q.window.end,
                        q.cadence.as_str(),
                        q.timezone.as_deref(),
                        None,
                        Some(net),
                    ))
                },
            )
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope)
                .with_network(network)
                .with_window(query.echo()),
        ))
    }

    #[tool(
        title = "Get data usage per eero",
        description = concat!(
            "Get data usage per eero (mesh node) over a time window: download and upload bytes ",
            "for each node, to see which node carries the most traffic. start and end are RFC ",
            "3339 timestamps and default to the last 7 days ending now (give one bound and the ",
            "other is derived 7 days away); cadence defaults to daily; timezone is an optional ",
            "IANA name passed to eero unchanged. The effective window is echoed in the window ",
            "member. network_id defaults to the account's only network. Not cached. Some ",
            "networks or firmware do not offer this report, and eero then answers not_found. If ",
            "eero refuses the report for the account's plan the call fails with ",
            "premium_required."
        ),
        annotations(
            title = "Get data usage per eero",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_eeros_data_usage(
        &self,
        Parameters(p): Parameters<UsageParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let choice = self.ids().network(p.network_id.as_ref())?;
        let query = UsageWindow::new(p.start.as_deref(), p.end.as_deref(), p.cadence, p.timezone)?;
        let network = self.resolve_network(choice).await?;
        let envelope = self
            .read_in(&network, &query, |c, net, q| {
                Box::pin(c.get_eeros_data_usage(
                    &q.window.start,
                    &q.window.end,
                    q.cadence.as_str(),
                    q.timezone.as_deref(),
                    None,
                    Some(net),
                ))
            })
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope)
                .with_network(network)
                .with_window(query.echo()),
        ))
    }

    #[tool(
        title = "Get profile data usage",
        description = concat!(
            "Get one household profile's data usage over a time window: the upload and ",
            "download byte series of the devices in that profile, bucketed daily or hourly. ",
            "profile_id is required (list_profiles shows the ids). start and end are RFC 3339 ",
            "timestamps and default to the last 7 days ending now (give one bound and the ",
            "other is derived 7 days away); cadence defaults to daily; timezone is an optional ",
            "IANA name passed to eero unchanged. The effective window is echoed in the window ",
            "member. network_id defaults to the account's only network. Not cached. If eero ",
            "refuses the report for the account's plan the call fails with premium_required."
        ),
        annotations(
            title = "Get profile data usage",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_profile_data_usage(
        &self,
        Parameters(p): Parameters<ProfileUsageParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let ids = self.ids();
        let choice = ids.network(p.network_id.as_ref())?;
        let child = ids.profile(&p.profile_id)?;
        let query = UsageWindow::new(p.start.as_deref(), p.end.as_deref(), p.cadence, p.timezone)?;
        let network = self.resolve_network(choice).await?;
        let profile = ids.in_network(&child, &network)?;
        let envelope = self
            .read_in_for(
                child.param(),
                &network,
                &(query.clone(), profile),
                |c, net, (q, profile)| {
                    Box::pin(c.get_profile_data_usage(
                        profile,
                        &q.window.start,
                        &q.window.end,
                        q.cadence.as_str(),
                        q.timezone.as_deref(),
                        None,
                        Some(net),
                    ))
                },
            )
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope)
                .with_network(network)
                .with_window(query.echo()),
        ))
    }

    #[tool(
        title = "Get insights",
        description = concat!(
            "Get network security and ad-block insights over a time window: how many requests ",
            "eero inspected, blocked or filtered in the chosen category, as a time series. ",
            "insight_type is one of inspected, blocked, malware, phishing, botnet, filtered, ",
            "adult, illegal, violent, adblock or datausage and defaults to blocked. start and ",
            "end are RFC 3339 timestamps and default to the last 7 days ending now (give one ",
            "bound and the other is derived 7 days away); cadence defaults to daily. The ",
            "effective window, cadence and insight_type are echoed in the window member. ",
            "network_id defaults to the account's only network. Not cached. Likely needs eero ",
            "Plus or eero Secure: without it the call fails with premium_required."
        ),
        annotations(
            title = "Get insights",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_insights(
        &self,
        Parameters(p): Parameters<InsightsParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let choice = self.ids().network(p.network_id.as_ref())?;
        let query = InsightWindow::new(
            p.start.as_deref(),
            p.end.as_deref(),
            p.cadence,
            p.insight_type,
        )?;
        let network = self.resolve_network(choice).await?;
        let envelope = self
            .read_in(&network, &query, |c, net, q| {
                // rusteero takes the insight type BEFORE the cadence on this one read.
                Box::pin(c.get_insights(
                    &q.window.start,
                    &q.window.end,
                    q.insight_type.as_str(),
                    q.cadence.as_str(),
                    Some(net),
                ))
            })
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope)
                .with_network(network)
                .with_window(query.echo()),
        ))
    }

    #[tool(
        title = "Get insights per device",
        description = concat!(
            "Get the same security and ad-block insights ranked per device over a time window: ",
            "for each device, how many requests eero inspected, blocked or filtered in the ",
            "chosen category. Use it to find which devices had the most blocked requests. ",
            "insight_type is one of inspected, blocked, malware, phishing, botnet, filtered, ",
            "adult, illegal, violent, adblock or datausage and defaults to blocked. start and ",
            "end are RFC 3339 timestamps and default to the last 7 days ending now (give one ",
            "bound and the other is derived 7 days away); cadence defaults to daily. The ",
            "effective window, cadence and insight_type are echoed in the window member. ",
            "network_id defaults to the account's only network. Not cached. Likely needs eero ",
            "Plus or eero Secure: without it the call fails with premium_required."
        ),
        annotations(
            title = "Get insights per device",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_devices_insights(
        &self,
        Parameters(p): Parameters<InsightsParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let choice = self.ids().network(p.network_id.as_ref())?;
        let query = InsightWindow::new(
            p.start.as_deref(),
            p.end.as_deref(),
            p.cadence,
            p.insight_type,
        )?;
        let network = self.resolve_network(choice).await?;
        let envelope = self
            .read_in(&network, &query, |c, net, q| {
                Box::pin(c.get_devices_insights(
                    &q.window.start,
                    &q.window.end,
                    q.cadence.as_str(),
                    q.insight_type.as_str(),
                    Some(net),
                ))
            })
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope)
                .with_network(network)
                .with_window(query.echo()),
        ))
    }

    #[tool(
        title = "Get device insights",
        description = concat!(
            "Get security and ad-block insights for one device over a time window: how many of ",
            "its requests eero inspected, blocked or filtered in the chosen category, as a ",
            "time series. device_id is required: a bare id, a MAC address in any common ",
            "spelling, or an API path or URL under the same network's devices (list_devices ",
            "shows them). insight_type is one of inspected, blocked, malware, phishing, botnet, ",
            "filtered, adult, illegal, violent, adblock or datausage and defaults to blocked. ",
            "start and end are RFC 3339 timestamps and default to the last 7 days ending now ",
            "(give one bound and the other is derived 7 days away); cadence defaults to daily. ",
            "The effective window, cadence and insight_type are echoed in the window member. ",
            "network_id defaults to the account's only network. Not cached. Likely needs eero ",
            "Plus or eero Secure: without it the call fails with premium_required."
        ),
        annotations(
            title = "Get device insights",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_device_insights(
        &self,
        Parameters(p): Parameters<DeviceInsightsParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let ids = self.ids();
        let choice = ids.network(p.network_id.as_ref())?;
        let child = ids.device(&p.device_id)?;
        let query = InsightWindow::new(
            p.start.as_deref(),
            p.end.as_deref(),
            p.cadence,
            p.insight_type,
        )?;
        let network = self.resolve_network(choice).await?;
        let device = ids.in_network(&child, &network)?;
        let envelope = self
            .read_in_for(
                child.param(),
                &network,
                &(query.clone(), device),
                |c, net, (q, device)| {
                    Box::pin(c.get_device_insights(
                        device,
                        &q.window.start,
                        &q.window.end,
                        q.cadence.as_str(),
                        q.insight_type.as_str(),
                        Some(net),
                    ))
                },
            )
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope)
                .with_network(network)
                .with_window(query.echo()),
        ))
    }
}
