//! The profiles group: tools 15 to 18.
//!
//! | # | Tool | rusteero read | Inputs (optional unless marked) |
//! |---|---|---|---|
//! | 15 | `list_profiles` | `get_profiles` (cached) | `network_id`, `refresh` |
//! | 16 | `get_profile` | `get_profile` (cached) | `profile_id` (required), `network_id`, `refresh` |
//! | 17 | `list_profile_schedules` | `get_schedules` | `profile_id` (required), `network_id` |
//! | 18 | `get_profile_blocked_apps` | `get_dns_policy_applications` (eero Plus) | `profile_id` (required), `network_id` |
//!
//! `list_profiles` is a plain network-scoped read. The other three forward a `profile_id`, so they
//! follow the child-id shape of [`crate::tools`]: validate the profile id and the network without
//! touching upstream, resolve the network, finish the profile's network check (a path or URL must
//! name the addressed network), then read through
//! [`EeroMcp::read_in_for`](crate::EeroMcp::read_in_for), which reports a rusteero id-field error
//! against `profile_id`.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{Json, tool, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::errors::ToolError;
use crate::output::ToolOutput;
use crate::params::{IdInput, NetworkRefreshParams, drop_default};
use crate::server::EeroMcp;

/// Input of `get_profile`.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileRefreshParams {
    /// Profile to read (required). Accepts a bare profile id, or an API path or URL under the
    /// same network's profiles, as a string or an integer. A profile's id is the last segment of
    /// its url in list_profiles.
    pub profile_id: IdInput,
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
}

/// Input of `list_profile_schedules` and `get_profile_blocked_apps`.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileParams {
    /// Profile to read (required). Accepts a bare profile id, or an API path or URL under the
    /// same network's profiles, as a string or an integer. A profile's id is the last segment of
    /// its url in list_profiles.
    pub profile_id: IdInput,
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
}

#[tool_router(router = profiles_router, vis = "pub(crate)")]
impl EeroMcp {
    #[tool(
        title = "List profiles",
        description = concat!(
            "List the household profiles on a network (the people or groups that devices are ",
            "assigned to): each profile's name, whether it is paused, its device references and ",
            "its content settings. A profile's id is the last segment of its url. Use it to find ",
            "a profile_id and to see which profiles are paused right now. network_id defaults ",
            "to the account's only network. Cached for 60 seconds; set refresh to bypass the ",
            "cache."
        ),
        annotations(
            title = "List profiles",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn list_profiles(
        &self,
        Parameters(p): Parameters<NetworkRefreshParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let refresh = p.refresh.unwrap_or(false);
        self.network_read(p.network_id.as_ref(), move |c, net| {
            Box::pin(c.get_profiles(Some(net), refresh))
        })
        .await
    }

    #[tool(
        title = "Get profile",
        description = concat!(
            "Get one household profile in full: its name, paused state, the devices assigned to ",
            "it and its content settings. profile_id is required (find it with list_profiles). ",
            "network_id defaults to the account's only network. Cached for 60 seconds; set ",
            "refresh to bypass the cache."
        ),
        annotations(
            title = "Get profile",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_profile(
        &self,
        Parameters(p): Parameters<ProfileRefreshParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let ids = self.ids();
        let choice = ids.network(p.network_id.as_ref())?;
        let child = ids.profile(&p.profile_id)?;
        let network = self.resolve_network(choice).await?;
        let profile = ids.in_network(&child, &network)?;
        let refresh = p.refresh.unwrap_or(false);
        let envelope = self
            .read_in_for(child.param(), &network, &profile, move |c, net, profile| {
                Box::pin(c.get_profile(profile, Some(net), refresh))
            })
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope).with_network(network),
        ))
    }

    #[tool(
        title = "List profile schedules",
        description = concat!(
            "List the scheduled pauses of one household profile (for example bedtime): each ",
            "schedule's name, days, start and end times and whether it is enabled. Use it to ",
            "answer when a profile's internet is paused. profile_id is required (find it with ",
            "list_profiles). network_id defaults to the account's only network. eero refuses ",
            "this read for some profiles and accounts: access_denied and not_found are ",
            "expected answers, not faults, so do not retry."
        ),
        annotations(
            title = "List profile schedules",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn list_profile_schedules(
        &self,
        Parameters(p): Parameters<ProfileParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let ids = self.ids();
        let choice = ids.network(p.network_id.as_ref())?;
        let child = ids.profile(&p.profile_id)?;
        let network = self.resolve_network(choice).await?;
        let profile = ids.in_network(&child, &network)?;
        let envelope = self
            .read_in_for(child.param(), &network, &profile, |c, net, profile| {
                Box::pin(c.get_schedules(profile, Some(net)))
            })
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope).with_network(network),
        ))
    }

    #[tool(
        title = "Get profile blocked apps",
        description = concat!(
            "Get the apps and app categories that can be blocked for one household profile, and ",
            "which of them are blocked. Requires eero Plus: without it the call fails with ",
            "premium_required. profile_id is required (find it with list_profiles). network_id ",
            "defaults to the account's only network."
        ),
        annotations(
            title = "Get profile blocked apps",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_profile_blocked_apps(
        &self,
        Parameters(p): Parameters<ProfileParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let ids = self.ids();
        let choice = ids.network(p.network_id.as_ref())?;
        let child = ids.profile(&p.profile_id)?;
        let network = self.resolve_network(choice).await?;
        let profile = ids.in_network(&child, &network)?;
        let envelope = self
            .read_in_for(child.param(), &network, &profile, |c, net, profile| {
                Box::pin(c.get_dns_policy_applications(profile, Some(net)))
            })
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope).with_network(network),
        ))
    }
}
