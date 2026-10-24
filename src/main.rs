//! The `eero-mcp` binary: a thin wrapper that wires the process around the library.
//!
//! Startup: help and version flags, tracing on stderr, configuration from the process environment,
//! read-only credential resolution, Client build, then rmcp serves over stdin and stdout until the
//! host closes the channel or the process is interrupted or terminated. stdout carries only
//! JSON-RPC; everything else goes to stderr.

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::Context as _;
use eero_mcp::config::{EnvMap, Settings};
use eero_mcp::credentials::{CredentialChain, Resolver, resolve_at_startup};
use eero_mcp::{EeroMcp, client_builder};
use rmcp::service::RunningService;
use rmcp::transport::stdio;
use rmcp::{RoleServer, ServiceExt as _};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
eero-mcp: a read-only MCP server for the eero mesh Wi-Fi cloud API (stdio transport)

USAGE:
    eero-mcp [OPTIONS]

OPTIONS:
    -h, --help       Print this help and exit
    -V, --version    Print the version and exit

ENVIRONMENT:
    RUSTEERO_SESSION_TOKEN   Session token (first credential source; changes need a restart)
    EERO_MCP_SESSION_FILE    Credential-record file (unreadable or unparsable fails startup)
    EEROCTL_CONFIG_DIR       eeroctl's configuration directory (default credential file)
    EERO_MCP_API_BASE_URL    Development and testing only: https, or http on a loopback host
    RUST_LOG                 Log filter for stderr (default: warn)

Debug logging: use RUST_LOG=eero_mcp=debug,rusteero=debug. A bare RUST_LOG=debug (or trace) also
enables rmcp, which logs every tool call's arguments and result (network names, MACs) to stderr.
Request paths in rusteero's debug lines contain network, eero and device ids: keep such logs on
this machine.

Without a token or file, the OS keyring entry shared with eeroctl is read (builds with the
keyring feature), then eeroctl's cookies.json. Credentials are only ever read.
";

fn main() -> ExitCode {
    // `args_os`, not `args`: an argument that is not valid UTF-8 must be the documented usage
    // error (status 2), not a panic that echoes it.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => {}
        [flag] if matches!(flag.to_str(), Some("-h" | "--help")) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        [flag] if matches!(flag.to_str(), Some("-V" | "--version")) => {
            println!("eero-mcp {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("eero-mcp: unexpected arguments (only --help and --version are accepted)");
            return ExitCode::from(2);
        }
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("eero-mcp: cannot start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(run());
    // After a termination signal the stdin reader may still be parked in a blocking read, and
    // dropping the runtime would wait for it until the host closes the pipe. Nothing is left to
    // flush, so do not wait.
    runtime.shutdown_background();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("eero-mcp: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    // stdout is the JSON-RPC channel: logs go to stderr, default filter warn.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    // Install the signal handlers before anything else: a signal that arrives during startup or
    // the handshake then ends the server cleanly (status 0) instead of killing the process. It
    // also interrupts a startup that is stuck, such as a keyring read waiting for an unlock.
    let mut shutdown = Shutdown::install().context("cannot install the signal handlers")?;

    let service = tokio::select! {
        started = start() => started?,
        () = shutdown.recv() => return Ok(()),
    };
    let cancel = service.cancellation_token();
    tokio::spawn(async move {
        shutdown.recv().await;
        cancel.cancel();
    });
    service
        .waiting()
        .await
        .context("the MCP server stopped abnormally")?;
    Ok(())
}

/// Resolves the configuration and the credential, builds the Client and starts serving over stdio
/// (the future completes once the handshake reply is written).
async fn start() -> anyhow::Result<RunningService<RoleServer, EeroMcp>> {
    let settings = Settings::from_env(&EnvMap::from_process())?;
    let chain = Arc::new(CredentialChain::from_settings(&settings));
    let token = resolve_at_startup(Arc::clone(&chain)).await?;
    if token.is_none() {
        tracing::warn!(
            "no eero credential found: set RUSTEERO_SESSION_TOKEN or EERO_MCP_SESSION_FILE, or \
             log in with eeroctl; every tool call returns authentication_required until then"
        );
    }

    let client = client_builder(settings.api_base_url.as_deref(), token.as_ref())
        .build()
        .await
        .context("cannot build the eero client (on Linux this needs system CA certificates)")?;
    let resolver = Resolver::new(chain);
    let server = EeroMcp::new(client, resolver);

    server
        .serve(stdio())
        .await
        .context("cannot start the MCP server on stdio")
}

/// The interrupt and termination signals, registered when installed so none is missed later.
struct Shutdown {
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
}

impl Shutdown {
    fn install() -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                terminate: signal(SignalKind::terminate())?,
                interrupt: signal(SignalKind::interrupt())?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                ctrl_c: tokio::signal::windows::ctrl_c()?,
            })
        }
    }

    /// Resolves on the next interrupt, or termination signal where the platform has one.
    async fn recv(&mut self) {
        #[cfg(unix)]
        tokio::select! {
            _ = self.terminate.recv() => {}
            _ = self.interrupt.recv() => {}
        }
        #[cfg(windows)]
        let _ = self.ctrl_c.recv().await;
    }
}
