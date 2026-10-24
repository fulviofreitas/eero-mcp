//! The seven tool groups, each its own rmcp tool router, merged into the server's router. The
//! merged router lists tools sorted by name.
//!
//! | Module | Tools |
//! |---|---|
//! | [`account`] | 1 to 7 |
//! | [`eeros`] | 8 to 10 |
//! | [`devices`] | 11 to 14 |
//! | [`profiles`] | 15 to 18 |
//! | [`health`] | 19 to 25 |
//! | [`network_config`] | 26 to 32 |
//! | [`usage`] | 33 to 40 |
//!
//! Adding a tool touches only its group module: write the handler inside that module's
//! `#[tool_router]` impl block, following [`account`].
//!
//! # Two compile-checked shapes beyond [`account`]
//!
//! Both shapes are exercised, line for line, by `tests/call_path.rs` (the same public building
//! blocks, composed outside a handler).
//!
//! A tool with a child id (`device_id`, `profile_id`): validate every input first (no upstream),
//! resolve the network, finish the child's network check, then read with
//! [`EeroMcp::read_in_for`](crate::EeroMcp::read_in_for), which reports a rusteero id-field error
//! against the child's own parameter. The child id travels through `args`; only `Copy` values are
//! captured:
//!
//! ```ignore
//! let ids = self.ids();
//! let choice = ids.network(p.network_id.as_ref())?;
//! let child = ids.device(&p.device_id)?;            // ids.profile(..) for profiles
//! let network = self.resolve_network(choice).await?;
//! let device = ids.in_network(&child, &network)?;   // canonical bare id, membership checked
//! let refresh = p.refresh.unwrap_or(false);
//! let envelope = self
//!     .read_in_for(child.param(), &network, &device, move |c, net, device| {
//!         Box::pin(c.get_device(device, Some(net), refresh))
//!     })
//!     .await?;
//! Ok(Json(ToolOutput::from_envelope(&envelope).with_network(network)))
//! ```
//!
//! A windowed tool: resolve the window and the enumerations before the network, pass them through
//! `args`, and echo the effective window:
//!
//! ```ignore
//! let choice = self.ids().network(p.network_id.as_ref())?;
//! let window = window::resolve(p.start.as_deref(), p.end.as_deref(), Span::Days7)?;
//! let cadence = p.cadence.unwrap_or_default();
//! let timezone = p.timezone;
//! let network = self.resolve_network(choice).await?;
//! let envelope = self
//!     .read_in(
//!         &network,
//!         &(window.clone(), cadence, timezone.clone()),
//!         |c, net, (window, cadence, timezone)| {
//!             Box::pin(c.get_data_usage(
//!                 &window.start, &window.end, cadence.as_str(), timezone.as_deref(), None, Some(net),
//!             ))
//!         },
//!     )
//!     .await?;
//! let echo = WindowEcho::new(window).cadence(cadence).timezone(timezone.as_deref());
//! Ok(Json(ToolOutput::from_envelope(&envelope).with_network(network).with_window(echo)))
//! ```

use std::borrow::Cow;
use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{JsonObject, Tool};
use serde_json::Value;

use crate::params::{collapse_whitespace, tidy_descriptions};
use crate::server::EeroMcp;

pub mod account;
pub mod devices;
pub mod eeros;
pub mod health;
pub mod network_config;
pub mod profiles;
pub mod usage;

/// All seven group routers merged into one.
///
/// Descriptions come from wrapped doc comments, whose line breaks schemars keeps; they are joined
/// here, once, for every tool and every schema.
pub(crate) fn router() -> ToolRouter<EeroMcp> {
    let mut router = EeroMcp::account_router()
        + EeroMcp::eeros_router()
        + EeroMcp::devices_router()
        + EeroMcp::profiles_router()
        + EeroMcp::health_router()
        + EeroMcp::network_config_router()
        + EeroMcp::usage_router();
    for route in router.map.values_mut() {
        tidy(&mut route.attr);
    }
    router
}

fn tidy_schema(schema: &JsonObject) -> Arc<JsonObject> {
    let mut value = Value::Object(schema.clone());
    tidy_descriptions(&mut value);
    match value {
        Value::Object(object) => Arc::new(object),
        _ => Arc::new(schema.clone()),
    }
}

fn tidy(tool: &mut Tool) {
    if let Some(description) = &tool.description {
        tool.description = Some(Cow::Owned(collapse_whitespace(description)));
    }
    tool.input_schema = tidy_schema(&tool.input_schema);
    tool.output_schema = tool.output_schema.as_deref().map(tidy_schema);
}
