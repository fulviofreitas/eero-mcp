//! The devices group: tools 11 to 14 (not implemented yet).
//!
//! | # | Tool | rusteero read | Inputs (optional unless marked) |
//! |---|---|---|---|
//! | 11 | `list_devices` | `get_devices` (cached; always unfiltered: pass `None` for both filters) | `network_id`, `refresh`, `detail` (`summary` default or `full`) |
//! | 12 | `get_device` | `get_device` (cached) | `device_id` (required), `network_id`, `refresh` |
//! | 13 | `list_blocked_devices` | `get_blacklist` | `network_id` |
//! | 14 | `get_transfer_stats` | `get_transfer_stats` | `network_id`, `device_id` (optional; omitted means network-wide) |
//!
//! Follow [`super::account`]. `list_devices` summary mode uses
//! [`crate::output::summarize_devices`] and [`crate::output::ToolOutput::with_detail`]. Validate
//! `device_id` with [`crate::ids::Ids::device`] and finish its network check with
//! [`crate::ids::Ids::in_network`] after [`crate::server::EeroMcp::resolve_network`].

use rmcp::tool_router;

use crate::server::EeroMcp;

#[tool_router(router = devices_router, vis = "pub(crate)", allow_empty)]
impl EeroMcp {}
