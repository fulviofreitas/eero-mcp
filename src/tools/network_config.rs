//! The `network_config` group: tools 26 to 32 (not implemented yet).
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
//! [`crate::server::EeroMcp::network_read`]. Follow [`super::account`].

use rmcp::tool_router;

use crate::server::EeroMcp;

#[tool_router(router = network_config_router, vis = "pub(crate)", allow_empty)]
impl EeroMcp {}
