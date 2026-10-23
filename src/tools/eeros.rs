//! The eeros group: tools 8 to 10 (not implemented yet).
//!
//! | # | Tool | rusteero read | Inputs (optional unless marked) |
//! |---|---|---|---|
//! | 8 | `list_eeros` | `get_eeros` (cached) | `network_id`, `refresh` |
//! | 9 | `get_eero` | `get_eero` (never cached: rusteero ignores its refresh flag, so there is no `refresh` input; always pass `false`) | `eero_id` (required), `network_id` |
//! | 10 | `list_eero_connections` | `get_connections` | `eero_id` (required), `network_id` |
//!
//! Follow [`super::account`]. Validate `eero_id` with [`crate::ids::Ids::eero`].

use rmcp::tool_router;

use crate::server::EeroMcp;

#[tool_router(router = eeros_router, vis = "pub(crate)", allow_empty)]
impl EeroMcp {}
