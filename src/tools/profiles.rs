//! The profiles group: tools 15 to 18 (not implemented yet).
//!
//! | # | Tool | rusteero read | Inputs (optional unless marked) |
//! |---|---|---|---|
//! | 15 | `list_profiles` | `get_profiles` (cached) | `network_id`, `refresh` |
//! | 16 | `get_profile` | `get_profile` (cached) | `profile_id` (required), `network_id`, `refresh` |
//! | 17 | `list_profile_schedules` | `get_schedules` | `profile_id` (required), `network_id` |
//! | 18 | `get_profile_blocked_apps` | `get_dns_policy_applications` (eero Plus) | `profile_id` (required), `network_id` |
//!
//! Follow [`super::account`]. Validate `profile_id` with [`crate::ids::Ids::profile`] and finish
//! its network check with [`crate::ids::Ids::in_network`] after
//! [`crate::server::EeroMcp::resolve_network`].

use rmcp::tool_router;

use crate::server::EeroMcp;

#[tool_router(router = profiles_router, vis = "pub(crate)", allow_empty)]
impl EeroMcp {}
