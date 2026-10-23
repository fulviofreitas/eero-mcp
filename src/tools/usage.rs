//! The usage group: tools 33 to 40 (not implemented yet).
//!
//! All eight are time-windowed (default last 7 days, `cadence` daily) and echo the effective
//! window with [`crate::output::WindowEcho`].
//!
//! | # | Tool | rusteero read | Inputs (optional unless marked) |
//! |---|---|---|---|
//! | 33 | `get_data_usage` | `get_data_usage` | `network_id`, `start`, `end`, `cadence`, `timezone` |
//! | 34 | `get_devices_data_usage` | `get_devices_data_usage` (always pass a cadence, default daily) | `network_id`, `start`, `end`, `cadence`, `timezone`, `profile_id` |
//! | 35 | `get_device_data_usage` | `get_device_data_usage` | `device_mac` (required), `network_id`, `start`, `end`, `cadence`, `timezone` |
//! | 36 | `get_eeros_data_usage` | `get_eeros_data_usage` | `network_id`, `start`, `end`, `cadence`, `timezone` |
//! | 37 | `get_profile_data_usage` | `get_profile_data_usage` | `profile_id` (required), `network_id`, `start`, `end`, `cadence`, `timezone` |
//! | 38 | `get_insights` | `get_insights` (likely eero Plus or Secure; this read takes `insight_type` before `cadence`) | `network_id`, `start`, `end`, `cadence`, `insight_type` |
//! | 39 | `get_devices_insights` | `get_devices_insights` | `network_id`, `start`, `end`, `cadence`, `insight_type` |
//! | 40 | `get_device_insights` | `get_device_insights` | `device_id` (required), `network_id`, `start`, `end`, `cadence`, `insight_type` |
//!
//! Tools 33 to 37 take rusteero's optional per-call timeout: always leave it unset. Follow
//! [`super::account`]; windows: [`crate::window::resolve`] with `Span::Days7`.

use rmcp::tool_router;

use crate::server::EeroMcp;

#[tool_router(router = usage_router, vis = "pub(crate)", allow_empty)]
impl EeroMcp {}
