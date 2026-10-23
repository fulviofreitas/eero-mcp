//! A read-only MCP server for the eero mesh Wi-Fi cloud API, built on [rusteero].
//!
//! The library holds everything testable; the `eero-mcp` binary is a thin wrapper that wires the
//! process (arguments, logging, configuration, credentials, stdio). Integration tests drive the
//! server through an in-process MCP client.
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`config`] | settings from an injectable environment map |
//! | [`credentials`] | the read-only credential chain and the re-read after an authentication failure |
//! | [`server`] | server state, hand-written server info, the single call path |
//! | [`params`] | shared tool inputs and portable-schema helpers |
//! | [`ids`] | id validation and canonicalisation, default-network resolution |
//! | [`window`] | time-window defaults and validation |
//! | [`output`] | the success object, list unwrapping, device summary |
//! | [`redact`] | exact-key secret redaction |
//! | [`errors`] | the tool error type and the rusteero error mapping |
//! | [`tools`] | one rmcp tool router per group, merged |
//!
//! The server never writes: it calls rusteero read methods only, attaches no credential store, and
//! reads credentials without modifying them.
//!
//! [rusteero]: https://github.com/fulviofreitas/rusteero

pub mod config;
pub mod credentials;
pub mod errors;
pub mod ids;
pub mod output;
pub mod params;
pub mod redact;
pub mod server;
pub mod tools;
pub mod window;

pub use credentials::Resolver;
pub use server::{EeroMcp, client_builder};
