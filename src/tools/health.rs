//! The health group: tools 19 to 25 (not implemented yet).
//!
//! | # | Tool | rusteero read | Inputs (optional unless marked) |
//! |---|---|---|---|
//! | 19 | `list_speed_tests` | `get_speed_tests` (no default window) | `network_id`, `limit` (1 to 100), `start`, `end` (RFC 3339, passed through unchanged) |
//! | 20 | `get_diagnostics` | `get_diagnostics` (latest results; never starts a run) | `network_id` |
//! | 21 | `get_firmware_updates` | `get_updates` | `network_id` |
//! | 22 | `get_channel_utilization` | `get_channel_utilization` (default window 24 h) | `network_id`, `start`, `end`, `eero_id`, `band`, `granularity`, `busy_threshold` |
//! | 23 | `get_network_scan` | `get_network_scan` | `network_id` |
//! | 24 | `list_activity_events` | `get_app_events` | `network_id`, `page_size` (1 to 100), `before` (RFC 3339 cursor, rusteero's timestamp argument) |
//! | 25 | `list_notifications` | `get_notification_history` | `network_id`, `before` (RFC 3339 cursor) |
//!
//! Follow [`super::account`]. Windows: [`crate::window`] (`Span::Hours24` for tool 22) and
//! [`crate::output::WindowEcho`]; pass-through timestamps: [`crate::window::check_timestamp`];
//! ranges: [`crate::params::limit`], [`crate::params::page_size`],
//! [`crate::params::positive_integer`].

use rmcp::tool_router;

use crate::server::EeroMcp;

#[tool_router(router = health_router, vis = "pub(crate)", allow_empty)]
impl EeroMcp {}
