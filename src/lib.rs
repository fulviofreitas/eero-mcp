//! An MCP server for the eero mesh Wi-Fi cloud API, built on [rusteero]: 40 read-only network
//! tools, and a login tool, with the login, logout and status subcommands of the binary.
//!
//! The library holds everything testable; the `eero-mcp` binary is a thin wrapper that wires the
//! process (arguments, logging, configuration, credentials, stdio). Integration tests drive the
//! server through an in-process MCP client.
//!
//! | Module | Responsibility |
//! |---|---|
//! | [`config`] | settings from an injectable environment map |
//! | [`credentials`] | the read-only credential chain and the re-read after an authentication failure |
//! | [`auth`] | the login driver, eero-mcp's own credential store, sign-out: the only module that writes a credential |
//! | [`cli`] | the login, logout and status subcommands |
//! | [`server`] | server state, hand-written server info, the single call path |
//! | [`params`] | shared tool inputs and portable-schema helpers |
//! | [`ids`] | id validation and canonicalisation, default-network resolution |
//! | [`window`] | time-window defaults and validation |
//! | [`output`] | the success object, list unwrapping, device summary |
//! | [`redact`] | exact-key secret redaction |
//! | [`errors`] | the tool error type and the rusteero error mapping |
//! | [`tools`] | one rmcp tool router per group, merged |
//!
//! The network tools never write: they call rusteero read methods only. The server's Client has no
//! credential store attached, and credentials are read without modifying them. Only the login
//! module ([`auth`]) signs in and out and writes a credential, and only eero-mcp's own.
//!
//! [rusteero]: https://github.com/fulviofreitas/rusteero

pub mod auth;
pub mod cli;
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
