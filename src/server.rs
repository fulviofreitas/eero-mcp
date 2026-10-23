//! The server: shared state, the hand-written server info and the single call path.
//!
//! [`EeroMcp`] owns the one rusteero [`Client`], a semaphore of [`MAX_CONCURRENT_READS`] permits,
//! the credential re-read lock and the re-reader. It is the only module that holds the Client, and
//! the only one that calls the Client's `set_session_token` (the credential re-read install; no
//! store is attached, so nothing is persisted). The token in use is always the Client's own
//! session; the server keeps no second copy that could go stale.
//!
//! # The call path
//!
//! Tool handlers validate their inputs (no upstream), resolve the network, then hand a read
//! closure to [`EeroMcp::read`] / [`EeroMcp::read_in`] / [`EeroMcp::read_in_for`] /
//! [`EeroMcp::network_read`]:
//!
//! 1. validate (types, ranges, timestamps, window order, ids): no permit is taken for invalid
//!    calls;
//! 2. resolve the network ([`EeroMcp::resolve_network`]): an explicit id, or the account's only
//!    network from the cached network list, which is itself a pass through the call path;
//! 3. take one of 4 permits, held for the read, the credential re-read and the single retry;
//! 4. run the read;
//! 5. on rusteero `Authentication`, re-read the credential chain once (serialised by a mutex) and,
//!    if it yields a token other than the one the failed call used (none, if the Client had no
//!    session), install it and retry the read exactly once;
//! 6. map any error ([`crate::errors::map_error`]);
//! 7. shape the output ([`crate::output::ToolOutput`], which always redacts).
//!
//! Handlers never touch credentials, transport or environment.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ServerCapabilities, ServerConfig};
use rmcp::{Json, ServerHandler, tool_handler};
use rusteero::{Client, ClientBuilder, Envelope, Error, Session};
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::{Mutex, Semaphore};

use crate::credentials::Resolver;
use crate::errors::{ToolError, map_error};
use crate::ids::{self, Ids, NetworkChoice};
use crate::output::{self, ToolOutput};
use crate::params::IdInput;

/// The server-wide cap on concurrent upstream calls. Agents fire parallel tool calls, rusteero does
/// not coalesce cache misses, and eero documents about 100 requests per minute.
pub const MAX_CONCURRENT_READS: usize = 4;

/// What a read closure returns: rusteero's future, boxed so the closure can be higher-ranked over
/// the borrows it is given.
pub type ReadFuture<'a> = Pin<Box<dyn Future<Output = Result<Envelope, Error>> + Send + 'a>>;

/// The agent-facing usage text of the server info.
pub const INSTRUCTIONS: &str = "Read-only access to an eero mesh Wi-Fi network: this server \
never changes anything. network_id is optional and defaults to the account's only network; \
with several networks, call list_networks and pass an id. refresh bypasses the 60 s cache on \
the tools that offer it. Some tools need eero Plus and return premium_required without it. On \
authentication_required, log in again with eeroctl (or eero-api) or set a fresh \
RUSTEERO_SESSION_TOKEN.";

/// The rusteero Client the way production builds it: an explicit session (or none), **no
/// credential store** (so rusteero can never clear, migrate or rewrite the shared credentials),
/// one GET retry (transport errors, timeouts and 5xx, after a fixed 500 ms; never for rate limits
/// or non-GET), and rusteero's defaults otherwise (60 s cache, 30 s and 10 s timeouts, User-Agent).
/// `api_base_url` is the validated `EERO_MCP_API_BASE_URL`, when set.
pub fn client_builder(api_base_url: Option<&str>, token: Option<&SecretString>) -> ClientBuilder {
    let mut builder = Client::builder().get_retries(1);
    if let Some(url) = api_base_url {
        builder = builder.base_url(url);
    }
    builder.session(token.map(|token| Session::from_token(token.expose_secret())))
}

/// Compares two tokens, exposing the secrets only for the equality check.
fn same_token(a: Option<&SecretString>, b: Option<&SecretString>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => a.expose_secret() == b.expose_secret(),
        _ => false,
    }
}

struct Shared {
    client: Client,
    permits: Semaphore,
    /// Serialises the credential re-read: one at a time.
    reread: Mutex<()>,
    resolver: Resolver,
}

/// The eero MCP server.
#[derive(Clone)]
pub struct EeroMcp {
    shared: Arc<Shared>,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for EeroMcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EeroMcp").finish_non_exhaustive()
    }
}

impl EeroMcp {
    /// Builds the server over an already built rusteero Client and the credential re-reader.
    pub fn new(client: Client, resolver: Resolver) -> Self {
        Self {
            shared: Arc::new(Shared {
                client,
                permits: Semaphore::new(MAX_CONCURRENT_READS),
                reread: Mutex::new(()),
                resolver,
            }),
            tool_router: crate::tools::router(),
        }
    }

    /// Id validators bound to the Client's configured API origin.
    pub fn ids(&self) -> Ids<'_> {
        Ids::for_client(&self.shared.client)
    }

    /// The token the Client is using right now: its own session, if it has a valid one.
    ///
    /// This is read from the Client every time rather than remembered here, because rusteero can
    /// clear its in-memory session on its own (a terminal session-refresh failure).
    fn installed_token(&self) -> Option<SecretString> {
        self.shared
            .client
            .session()
            .filter(Session::is_valid)
            .map(|session| session.token().clone())
    }

    /// Whether `result` is an authentication failure that a credential re-read fixed, so the read
    /// should run once more. Call with the permit held.
    async fn should_retry(
        &self,
        result: &Result<Envelope, Error>,
        used: Option<&SecretString>,
    ) -> bool {
        matches!(result, Err(Error::Authentication { .. })) && self.reread_and_install(used).await
    }

    /// The credential re-read: one re-read at a time; a different token is installed in memory
    /// (rusteero clears its cache; nothing is persisted) unless a concurrent call already
    /// installed it. Returns whether the read should be retried.
    ///
    /// `used` is the token the failed call went out with (`None`: the Client had no session).
    async fn reread_and_install(&self, used: Option<&SecretString>) -> bool {
        let shared = &*self.shared;
        let _serialised = shared.reread.lock().await;

        // A concurrent call installed a newer token while this one waited for the lock. A Client
        // with no session at all is not that case (rusteero cleared it after a failed session
        // refresh, or none was ever set): fall through and ask the sources.
        let installed = self.installed_token();
        if installed.is_some() && !same_token(installed.as_ref(), used) {
            return true;
        }
        let Some(found) = shared.resolver.reread().await else {
            tracing::debug!("credential re-read found no credential");
            return false;
        };
        if same_token(Some(&found), used) {
            tracing::debug!("credential re-read found the token already in use");
            return false;
        }
        if shared
            .client
            .set_session_token(found.expose_secret())
            .await
            .is_err()
        {
            tracing::warn!("a re-read credential was rejected by the client");
            return false;
        }
        tracing::debug!("installed a re-read credential");
        true
    }

    /// The single call path for a read with arguments. See the module docs.
    ///
    /// `id_param` is the tool parameter that rusteero's id-field validation errors are reported
    /// against (`None` for reads that forward no id).
    async fn read_with<A, F>(
        &self,
        id_param: Option<&'static str>,
        args: &A,
        read: F,
    ) -> Result<Envelope, ToolError>
    where
        A: Sync,
        F: for<'a> Fn(&'a Client, &'a A) -> ReadFuture<'a> + Send + Sync,
    {
        let shared = &*self.shared;
        let _permit = shared
            .permits
            .acquire()
            .await
            .map_err(|_| ToolError::internal())?;
        let used = self.installed_token();
        let mut result = read(&shared.client, args).await;
        if self.should_retry(&result, used.as_ref()).await {
            result = read(&shared.client, args).await;
        }
        result.map_err(|error| map_error(&error, id_param))
    }

    /// An account-level read (no network): `get_account`, `list_networks`.
    ///
    /// ```ignore
    /// let envelope = self.read(|c| Box::pin(c.get_account(refresh))).await?;
    /// ```
    pub async fn read<F>(&self, read: F) -> Result<Envelope, ToolError>
    where
        F: for<'a> Fn(&'a Client) -> ReadFuture<'a> + Send + Sync,
    {
        self.read_with(None, &(), |client, ()| read(client)).await
    }

    /// A read in a resolved network, with extra validated arguments.
    ///
    /// The closure receives the Client, the canonical network id and `args`; it must be a single
    /// `Box::pin(client.some_read(...))` expression and must capture nothing that is borrowed
    /// (put every value the read needs into `args`):
    ///
    /// ```ignore
    /// let envelope = self
    ///     .read_in(&network, &(window.clone(), cadence), |c, net, (window, cadence)| {
    ///         Box::pin(c.get_data_usage(&window.start, &window.end, cadence.as_str(), None, None, Some(net)))
    ///     })
    ///     .await?;
    /// ```
    ///
    /// An id-field validation error raised by rusteero inside the read is reported against
    /// `network_id`. A tool that forwards a device or profile id uses [`EeroMcp::read_in_for`].
    pub async fn read_in<A, F>(
        &self,
        network_id: &str,
        args: &A,
        read: F,
    ) -> Result<Envelope, ToolError>
    where
        A: Sync,
        F: for<'a> Fn(&'a Client, &'a str, &'a A) -> ReadFuture<'a> + Send + Sync,
    {
        self.read_in_for("network_id", network_id, args, read).await
    }

    /// As [`EeroMcp::read_in`], for a tool that forwards a child id: an id-field validation error
    /// raised by rusteero inside the read is reported against `id_param`, the most specific id the
    /// read forwards (take it from [`crate::ids::ChildId::param`]).
    ///
    /// ```ignore
    /// let child = ids.device(&p.device_id)?;
    /// let network = self.resolve_network(choice).await?;
    /// let device = ids.in_network(&child, &network)?;
    /// let envelope = self
    ///     .read_in_for(child.param(), &network, &device, move |c, net, device| {
    ///         Box::pin(c.get_device(device, Some(net), refresh))
    ///     })
    ///     .await?;
    /// ```
    pub async fn read_in_for<A, F>(
        &self,
        id_param: &'static str,
        network_id: &str,
        args: &A,
        read: F,
    ) -> Result<Envelope, ToolError>
    where
        A: Sync,
        F: for<'a> Fn(&'a Client, &'a str, &'a A) -> ReadFuture<'a> + Send + Sync,
    {
        self.read_with(
            Some(id_param),
            &(network_id, args),
            |client, &(network_id, args)| read(client, network_id, args),
        )
        .await
    }

    /// Resolves the network a tool queries: an explicit canonical id as is, otherwise the
    /// account's only network from rusteero's cached network list (60 s, never refreshed here).
    /// Zero networks is `not_found`; several is `invalid_argument` listing each id and name.
    pub async fn resolve_network(&self, choice: NetworkChoice) -> Result<String, ToolError> {
        match choice {
            NetworkChoice::Explicit(id) => Ok(id),
            NetworkChoice::Default => {
                let envelope = self.read(|c| Box::pin(c.get_networks(false))).await?;
                ids::pick_default_network(&output::unwrap_network_list(envelope.data()))
            }
        }
    }

    /// The common shape of a network-scoped tool whose output is the envelope's data as is:
    /// validate `network_id`, resolve the network, read, and return the redacted output carrying
    /// the network actually queried.
    ///
    /// ```ignore
    /// self.network_read(p.network_id.as_ref(), |c, net| Box::pin(c.get_members(Some(net)))).await
    /// ```
    pub async fn network_read<F>(
        &self,
        network_id: Option<&IdInput>,
        read: F,
    ) -> Result<Json<ToolOutput>, ToolError>
    where
        F: for<'a> Fn(&'a Client, &'a str) -> ReadFuture<'a> + Send + Sync,
    {
        let choice = self.ids().network(network_id)?;
        let network = self.resolve_network(choice).await?;
        let envelope = self
            .read_in(&network, &(), |client, network_id, ()| {
                read(client, network_id)
            })
            .await?;
        Ok(Json(
            ToolOutput::from_envelope(&envelope).with_network(network),
        ))
    }
}

#[tool_handler(router = self.tool_router)]
#[allow(clippy::unused_async_trait_impl)]
impl ServerHandler for EeroMcp {
    /// Written by hand: rmcp's generated default reports `rmcp` and its own version, because its
    /// build-environment helper expands inside the rmcp crate.
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
                    .with_title("eero (read-only)"),
            )
            .with_instructions(INSTRUCTIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_token_compares_values_not_identity() {
        let a = SecretString::from("token-a".to_owned());
        let a2 = SecretString::from("token-a".to_owned());
        let b = SecretString::from("token-b".to_owned());
        assert!(same_token(Some(&a), Some(&a2)));
        assert!(!same_token(Some(&a), Some(&b)));
        assert!(!same_token(Some(&a), None));
        assert!(!same_token(None, Some(&a)));
        assert!(same_token(None, None));
    }

    #[test]
    fn the_instructions_cover_the_documented_guidance() {
        for needle in [
            "Read-only",
            "network_id",
            "list_networks",
            "refresh",
            "60 s",
            "eero Plus",
            "authentication_required",
            "eeroctl",
        ] {
            assert!(INSTRUCTIONS.contains(needle), "{needle}");
        }
    }

    #[test]
    fn the_permit_count_is_four() {
        assert_eq!(MAX_CONCURRENT_READS, 4);
    }
}
