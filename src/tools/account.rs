//! The account group: tools 1 to 7.
//!
//! | # | Tool | rusteero read | Inputs |
//! |---|---|---|---|
//! | 1 | `get_account` | `get_account` (cached) | `refresh` |
//! | 2 | `list_networks` | `get_networks` (cached) | `refresh` |
//! | 3 | `get_network` | `get_network` (cached) | `network_id`, `refresh` |
//! | 4 | `get_guest_network` | `get_guest_network` | `network_id` |
//! | 5 | `list_network_members` | `get_members` | `network_id` |
//! | 6 | `get_network_permissions` | `get_permissions` | `network_id` |
//! | 7 | `get_premium_features` | `get_entitlement_features` | `network_id` |
//!
//! # The pattern every other group follows
//!
//! A tool is one `async fn` inside a `#[tool_router]` impl block:
//!
//! 1. **Input**: `Parameters<P>` where `P` is a `Deserialize + JsonSchema` struct with
//!    `#[serde(deny_unknown_fields)]`. Reuse [`crate::params::NetworkParams`],
//!    [`crate::params::NetworkRefreshParams`] or [`crate::params::RefreshParams`], or declare a
//!    struct whose optional fields follow the recipe in [`crate::params`].
//! 2. **Attribute**: `#[tool(title, description, annotations(...))]` with the four read-only
//!    annotations, exactly as below. The description says what the tool returns and any eero
//!    Plus gating.
//! 3. **Return type**: written out as `Result<Json<ToolOutput>, ToolError>` (the macro derives
//!    the `outputSchema` from this literal spelling; a type alias would hide it).
//! 4. **Body**: validate inputs without touching upstream, resolve the network, then call the
//!    shared call path with a read closure. `network_read` covers a network-scoped read whose
//!    output is the envelope data as is; `read_in` (`read_in_for` when a child id is forwarded) and
//!    `resolve_network` are the building blocks for tools with child ids, windows or custom
//!    shaping. See [`crate::tools`] for both shapes.
//!
//! A read closure is a single `Box::pin(client.some_read(...))` expression. It may capture only
//! `Copy` values (`move |c, net| ...`); anything borrowed goes through the `args` of `read_in`.

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{Json, tool, tool_router};
use serde_json::Value;

use crate::errors::ToolError;
use crate::output::{ToolOutput, unwrap_network_list};
use crate::params::{NetworkParams, NetworkRefreshParams, RefreshParams};
use crate::server::EeroMcp;

#[tool_router(router = account_router, vis = "pub(crate)")]
impl EeroMcp {
    #[tool(
        title = "Get account",
        description = concat!(
            "Get the signed-in eero account: owner name and contact details, premium ",
            "(eero Plus or eero Secure) status and references to the networks on the account. ",
            "Cached for 60 seconds; set refresh to bypass the cache. Secret values are redacted."
        ),
        annotations(
            title = "Get account",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_account(
        &self,
        Parameters(p): Parameters<RefreshParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let refresh = p.refresh.unwrap_or(false);
        let envelope = self.read(move |c| Box::pin(c.get_account(refresh))).await?;
        Ok(Json(ToolOutput::from_envelope(&envelope)))
    }

    #[tool(
        title = "List networks",
        description = concat!(
            "List the networks on the account as one array of network entries (url, name, ",
            "status and more), whichever container shape eero sends. Use it to find a ",
            "network_id. Cached for 60 seconds; set refresh to bypass the cache. Wi-Fi ",
            "passwords are redacted."
        ),
        annotations(
            title = "List networks",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn list_networks(
        &self,
        Parameters(p): Parameters<RefreshParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let refresh = p.refresh.unwrap_or(false);
        let envelope = self
            .read(move |c| Box::pin(c.get_networks(refresh)))
            .await?;
        let networks = Value::Array(unwrap_network_list(envelope.data()));
        Ok(Json(ToolOutput::from_envelope_with_data(
            &envelope, &networks,
        )))
    }

    #[tool(
        title = "Get network",
        description = concat!(
            "Get one network in full: health and status, DNS, SQM, security and Wi-Fi ",
            "settings, speeds and premium status. The richest single view of a network's ",
            "health and configuration. network_id defaults to the account's only network. ",
            "Cached for 60 seconds; set refresh to bypass the cache. Wi-Fi and guest ",
            "passwords are redacted."
        ),
        annotations(
            title = "Get network",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_network(
        &self,
        Parameters(p): Parameters<NetworkRefreshParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        let refresh = p.refresh.unwrap_or(false);
        self.network_read(p.network_id.as_ref(), move |c, net| {
            Box::pin(c.get_network(Some(net), refresh))
        })
        .await
    }

    #[tool(
        title = "Get guest network",
        description = concat!(
            "Get the guest Wi-Fi state of a network: whether it is enabled, its name and its ",
            "settings. The guest password is redacted. network_id defaults to the account's ",
            "only network."
        ),
        annotations(
            title = "Get guest network",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_guest_network(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_guest_network(Some(net)))
        })
        .await
    }

    #[tool(
        title = "List network members",
        description = concat!(
            "List who administers a network: the owner and the admins, as eero lists them. ",
            "network_id defaults to the account's only network."
        ),
        annotations(
            title = "List network members",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn list_network_members(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_members(Some(net)))
        })
        .await
    }

    #[tool(
        title = "Get network permissions",
        description = concat!(
            "Get what the signed-in account may do on a network, as eero reports its ",
            "permissions. network_id defaults to the account's only network."
        ),
        annotations(
            title = "Get network permissions",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_network_permissions(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_permissions(Some(net)))
        })
        .await
    }

    #[tool(
        title = "Get premium features",
        description = concat!(
            "List which eero Plus and eero Secure features are active on a network (the ",
            "entitlement feature list). network_id defaults to the account's only network."
        ),
        annotations(
            title = "Get premium features",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_premium_features(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_entitlement_features(Some(net)))
        })
        .await
    }
}
