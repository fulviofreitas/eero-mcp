//! The `network_config` group: tools 26 to 32.
//!
//! | # | Tool | rusteero read | Inputs |
//! |---|---|---|---|
//! | 26 | `list_port_forwards` | `get_forwards` | `network_id` |
//! | 27 | `list_dhcp_reservations` | `get_reservations` | `network_id` |
//! | 28 | `get_subnets` | `get_subnets_config` | `network_id` |
//! | 29 | `get_wpa3_settings` | `get_wpa3_per_band` | `network_id` |
//! | 30 | `get_fast_transition` | `get_fast_transition` | `network_id` |
//! | 31 | `get_content_filter` | `get_advanced_content_filter` (eero Plus) | `network_id` |
//! | 32 | `get_backup_internet` | `get_backup_internet` (eero Plus) | `network_id` |
//!
//! All seven take [`crate::params::NetworkParams`] and fit
//! [`EeroMcp::network_read`](crate::EeroMcp::network_read): none is cached, so none takes
//! `refresh`, and the output is the envelope's data as is (redacted).

use rmcp::handler::server::wrapper::Parameters;
use rmcp::{Json, tool, tool_router};

use crate::errors::ToolError;
use crate::output::ToolOutput;
use crate::params::NetworkParams;
use crate::server::EeroMcp;

#[tool_router(router = network_config_router, vis = "pub(crate)")]
impl EeroMcp {
    #[tool(
        title = "List port forwards",
        description = concat!(
            "List the port-forwarding rules on a network, that is which ports are exposed to the ",
            "internet and to which device and address. network_id defaults to the account's only ",
            "network."
        ),
        annotations(
            title = "List port forwards",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn list_port_forwards(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_forwards(Some(net)))
        })
        .await
    }

    #[tool(
        title = "List DHCP reservations",
        description = concat!(
            "List the DHCP reservations on a network: the fixed IP addresses assigned to ",
            "devices, by device address. Use it to find which device has a fixed IP. network_id ",
            "defaults to the account's only network."
        ),
        annotations(
            title = "List DHCP reservations",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn list_dhcp_reservations(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_reservations(Some(net)))
        })
        .await
    }

    #[tool(
        title = "Get subnets",
        description = concat!(
            "Get the subnet configuration of a network: how it is split into subnets such as the ",
            "guest and IoT segments, with their address ranges and settings. Subnet Wi-Fi ",
            "passwords are redacted. network_id defaults to the account's only network."
        ),
        annotations(
            title = "Get subnets",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_subnets(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_subnets_config(Some(net)))
        })
        .await
    }

    #[tool(
        title = "Get WPA3 settings",
        description = concat!(
            "Get the WPA3 mode of each Wi-Fi band of a network (WPA2, WPA2 and WPA3 mixed, or ",
            "WPA3). Useful when an older device fails to join or roam. network_id defaults to ",
            "the account's only network."
        ),
        annotations(
            title = "Get WPA3 settings",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_wpa3_settings(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_wpa3_per_band(Some(net)))
        })
        .await
    }

    #[tool(
        title = "Get fast transition",
        description = concat!(
            "Get whether fast transition (802.11r fast roaming) is enabled on a network. Useful ",
            "when a device has trouble roaming between eeros. network_id defaults to the ",
            "account's only network."
        ),
        annotations(
            title = "Get fast transition",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_fast_transition(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_fast_transition(Some(net)))
        })
        .await
    }

    #[tool(
        title = "Get content filter",
        description = concat!(
            "Get the advanced content filter's allow and block lists: each domain entry says ",
            "whether it applies to the whole network (applied_to_network) or only to the ",
            "profiles in its profile_list. Requires eero Plus: without it the call fails with ",
            "premium_required. network_id defaults to the account's only network."
        ),
        annotations(
            title = "Get content filter",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_content_filter(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_advanced_content_filter(Some(net)))
        })
        .await
    }

    #[tool(
        title = "Get backup internet",
        description = concat!(
            "Get the backup internet configuration of a network: whether a cellular backup ",
            "connection is enabled to take over when the main connection fails. Requires eero ",
            "Plus: without it the call fails with premium_required. Secret values are ",
            "redacted. network_id defaults to the account's only network."
        ),
        annotations(
            title = "Get backup internet",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn get_backup_internet(
        &self,
        Parameters(p): Parameters<NetworkParams>,
    ) -> Result<Json<ToolOutput>, ToolError> {
        self.network_read(p.network_id.as_ref(), |c, net| {
            Box::pin(c.get_backup_internet(Some(net)))
        })
        .await
    }
}
