//! The read-only guard: scans every file under `src/` and fails if the source could issue a write.
//!
//! The network tools' source must be *unable* to issue a write, not merely told not to.
//! Identifier-boundary matches count wherever they appear, comments included: `src/` never names
//! them. What is banned:
//!
//! - every rusteero `Client` / `ClientBuilder` method that is not one of the 40 catalogue reads
//!   (writes and actions, session and credential-store setters, and the 38 reads that no tool
//!   exposes), generated from rusteero 3.0.x and cross-checked against the dependency's real
//!   source by `every_public_client_function_is_classified`;
//! - the credential-store and login types, and the lower layers that bypass the Client: the
//!   transport, the endpoint API types, the route and endpoint tables, the storage helpers, the
//!   explicit session setters and the session refresh;
//! - the keyring crate beyond one read: outside `#[cfg(test)]` code `keyring::` may only name
//!   `Entry::new` and `Error::NoEntry`, the entry's public `inner` handle and every write or
//!   escape-hatch method of the keyring crates are banned, and so is every file-system write and
//!   every call that changes a file through an open handle (permissions, times, length);
//! - `Session::from_env` (it reads the real process environment).
//!
//! From 0.2.0 one module signs in and out: `src/auth.rs`, the login module. Only there may the
//! source name rusteero's login flow and pending login, the credential-store types with their
//! `save` / `clear` (and the blocking-pool adapters `save_async` / `clear_async`), the transport
//! builder that gives the login flow its base URL, and the Client's `logout`. Each is pinned
//! further: the keyring store only through `with_entry` carrying eero-mcp's own service and
//! account constants; the file store, the chained store and the login flow only through their
//! one constructor; the transport only through its builder, whose `builder` and `base_url` are
//! used exactly once each; rusteero reached only through the exact paths in
//! [`AUTH_RUSTEERO_PATHS`]. In `src/auth.rs` the guard also fails on any `load`, the shared
//! keyring constants, eeroctl's and the explicit file's settings, and the in-memory store, the
//! storage factory and its configuration; and the unit-test module of `src/auth.rs` may not name
//! a store or a mock server (those tests live in `tests/auth.rs`).
//!
//! The login module's public wrappers are pinned too, so that a read tool (or any other file)
//! cannot reach the store, the login or the sign-out through them: `run_login`, `save_session` and
//! `revoke_replaced` only in `src/auth.rs`, `src/cli.rs` and `src/tools/login.rs`; `revoke_session`
//! and `sign_out_own_session` only in `src/auth.rs` and `src/cli.rs`; `clear_all` only in
//! `src/auth.rs`; `OwnStore::production` only in `src/auth.rs`, `src/cli.rs` and `src/main.rs`. The
//! injectable constructor `OwnStore::with_backends` (for `tests/auth.rs`) is defined once and never
//! named anywhere else in `src/`. Every mention of a store type in `src/auth.rs` must be its one
//! pinned constructor with pinned arguments (or an import), `Default` and `default` are banned
//! there, and no import from rusteero may be renamed (`as`) anywhere in `src/`, so no spelling can
//! build the shared keyring entry or hide a type. The settings' own-file path is named only in
//! `src/config.rs`, `src/credentials.rs` and `src/auth.rs` (once, as `settings.own_file.clone()`),
//! so no other file can point the store at another file by rewriting it.
//!
//! The names without an underscore (`logout`, `store`) count when they are called, called with a
//! turbofish, or reached through a path (`Client::logout` taken as a function value).
//!
//! Where the session token can be sent is pinned too: building a Client (`builder`, `base_url`)
//! and reading its session (`session`) are allowed in `src/server.rs` only, and `base_url` is
//! applied exactly once there.
//!
//! Two exceptions are pinned to one site each, matched as that exact chain, and anything else
//! fails, whatever the call syntax (`client.api()`, `Client::api(&client)`, `rusteero::Client::api`):
//!
//! - `src/ids.rs` reads the configured API host through the Client's API accessor, then its
//!   transport, then `api_host`, exactly once (rusteero exposes the host no other way).
//! - `src/server.rs` uses the Client's async session-token setter exactly once (called, or taken
//!   as a function value), for the credential re-read. It changes in-memory state only, because no
//!   store is attached.
//!
//! The banned lists are generated from rusteero 3.0.x's `Client` (`src/client/*.rs`): every public
//! function that is not one of its 78 reads, minus the read-only accessors and harmless builder
//! setters; plus the 38 reads that are not part of the 40-tool catalogue. After a rusteero bump the
//! drift test names every function that needs classifying; the lists are regenerated with:
//!
//! ```text
//! for f in $(git -C <rusteero> ls-tree --name-only v3.0.1 src/client/); do
//!   git -C <rusteero> show "v3.0.1:$f" | grep -oE 'pub (async )?fn [a-z0-9_]+'
//! done | awk '{print $NF}' | sort -u
//! ```

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every non-read `Client` and `ClientBuilder` method of rusteero 3.0.x (the pinned
/// session-token setter and the read-only accessors excluded).
const WRITE_AND_ACTION_METHODS: &[&str] = &[
    "add_backup_access_point",
    "add_to_blacklist",
    "allow_cnames",
    "allow_cnames_for_profiles",
    "allow_domain",
    "allow_domain_for_profiles",
    "apply_update",
    "backup_connectivity_check",
    "block_device",
    "block_domain",
    "block_domain_for_profiles",
    "cancel_pending_admin",
    "clear_auth_data",
    "clear_cache",
    "clear_custom_dns",
    "clear_guest_password",
    "clear_network_password",
    "clear_profile_schedule",
    "clear_session_token",
    "configure_security",
    "create_burst_reporter",
    "create_forward",
    "create_invite",
    "create_power_saving_schedule",
    "create_profile",
    "create_reservation",
    "create_schedule",
    "delete_backup_access_point",
    "delete_forward",
    "delete_invite",
    "delete_power_saving_schedule",
    "delete_profile",
    "delete_reservation",
    "delete_schedule",
    "delete_subnet",
    "disable_ddns",
    "enable_bedtime",
    "enable_ddns",
    "http_builder",
    "led_cycle",
    "logout",
    "mark_notifications_read",
    "nightlight_override",
    "node_action",
    "pause_device",
    "pause_profile",
    "port_action",
    "promote_member",
    "query_invite",
    "rearrange_backup_access_points",
    "reboot_eero",
    "reboot_network",
    "regenerate_thread_credentials",
    "remove_admin",
    "remove_from_blacklist",
    "rename_profile",
    "request_support",
    "respond_to_invite",
    "run_diagnostics",
    "run_speed_test",
    "set_account_consents",
    "set_account_email",
    "set_account_name",
    "set_account_phone",
    "set_backup_internet",
    "set_band_steering",
    "set_connection_mode",
    "set_custom_dns",
    "set_custom_dns_ipv4",
    "set_custom_dns_ipv6",
    "set_data_usage_report_settings",
    "set_device_labels",
    "set_device_nickname",
    "set_device_secondary_wan_access",
    "set_device_type",
    "set_dhcp",
    "set_dns_caching",
    "set_dns_mode",
    "set_fast_transition",
    "set_guest_network",
    "set_guest_password",
    "set_hide_5g",
    "set_ipv6",
    "set_ipv6_upstream",
    "set_led",
    "set_led_brightness",
    "set_location",
    "set_mlo_mode",
    "set_multistaticip",
    "set_nat_port_randomization",
    "set_network_ad_block",
    "set_network_block_malware",
    "set_network_name",
    "set_network_password",
    "set_nightlight",
    "set_nightlight_brightness",
    "set_nightlight_schedule",
    "set_notification_settings",
    "set_passpoint_enabled",
    "set_power_saving",
    "set_pppoe",
    "set_preferred_network",
    "set_preferred_update_hour",
    "set_profile_blocked_applications",
    "set_profile_devices",
    "set_proxied_nodes",
    "set_push_settings",
    "set_secondary_wan_config",
    "set_sqm",
    "set_subnet_content_filters",
    "set_subnets_config",
    "set_thread_enabled",
    "set_upnp",
    "set_weekday_bedtime",
    "set_weekend_bedtime",
    "set_wpa3",
    "set_wpa3_per_band",
    "start_backup_ssid_discovery",
    "store",
    "unblock_device",
    "update_backup_access_point",
    "update_device_via_link",
    "update_forward",
    "update_invite",
    "update_power_saving_schedule",
    "update_reservation",
    "update_schedule",
    "update_thread",
    "verify_account_email",
    "verify_account_phone",
];

/// The 38 reads of rusteero 3.0.x that are not among the 40 catalogue tools: never called.
const UNEXPOSED_READS: &[&str] = &[
    "discover_backup_ssids",
    "get_ac_compat",
    "get_cellular_backup_events",
    "get_cellular_backup_usage",
    "get_data_usage_breakdown",
    "get_data_usage_report_settings",
    "get_device_labels",
    "get_device_priority",
    "get_dns_settings",
    "get_eero_data_usage",
    "get_eero_support",
    "get_eeros_data_usage_summary",
    "get_invites",
    "get_led_status",
    "get_model_capabilities",
    "get_multistaticip",
    "get_nightlight",
    "get_notification_settings",
    "get_ouicheck",
    "get_power_saving_schedules",
    "get_premium_customer",
    "get_premium_status",
    "get_profile_devices",
    "get_profile_devices_insights",
    "get_profile_insights",
    "get_profiles_insights",
    "get_routing",
    "get_security_settings",
    "get_sms_countries",
    "get_sqm_settings",
    "get_subnet_content_filters",
    "get_support",
    "get_thread",
    "get_unprofiled_data_usage_summary",
    "get_unprofiled_devices_data_usage",
    "get_upsell_features",
    "has_unread_notifications",
    "list_backup_access_points",
];

/// The 40 reads the catalogue calls (one per tool).
const CATALOGUE_READS: &[&str] = &[
    "get_account",
    "get_networks",
    "get_network",
    "get_guest_network",
    "get_members",
    "get_permissions",
    "get_entitlement_features",
    "get_eeros",
    "get_eero",
    "get_connections",
    "get_devices",
    "get_device",
    "get_blacklist",
    "get_transfer_stats",
    "get_profiles",
    "get_profile",
    "get_schedules",
    "get_dns_policy_applications",
    "get_speed_tests",
    "get_diagnostics",
    "get_updates",
    "get_channel_utilization",
    "get_network_scan",
    "get_app_events",
    "get_notification_history",
    "get_forwards",
    "get_reservations",
    "get_subnets_config",
    "get_wpa3_per_band",
    "get_fast_transition",
    "get_advanced_content_filter",
    "get_backup_internet",
    "get_data_usage",
    "get_devices_data_usage",
    "get_device_data_usage",
    "get_eeros_data_usage",
    "get_profile_data_usage",
    "get_insights",
    "get_devices_insights",
    "get_device_insights",
];

/// The 15 public `Client` / `ClientBuilder` functions that are neither reads nor writes: read-only
/// accessors and builder setters for harmless settings. `api` and `set_session_token` are among
/// them but are checked at their pinned sites instead.
const ALLOWED_CLIENT_ITEMS: &[&str] = &[
    "accept_language",
    "api",
    "base_url",
    "build",
    "builder",
    "cache_ttl",
    "credentials_persisted",
    "get_retries",
    "is_authenticated",
    "preferred_network_id",
    "send_legacy_cookie",
    "session",
    "set_session_token",
    "storage_failures",
    "user_agent",
];

/// Credential-store, login and low-level request types: none may be named in `src/`.
const BANNED_TYPES: &[&str] = &[
    "FileStore",
    "KeyringStore",
    "ChainedStore",
    "MemoryStore",
    "CredentialStore",
    "LoginFlow",
    "PendingLogin",
    "EeroApi",
    "AuthApi",
    "Transport",
    "TransportBuilder",
    "RequestBody",
    "StorageConfig",
];

/// Functions below the `Client` that write, refresh or bypass it, the keyring crates' write and
/// escape-hatch calls, and the file-handle calls that change a file without opening it for writing
/// (`fchmod` and `futimens` work on a read-only descriptor). Every name contains an underscore, so
/// each counts anywhere it appears.
const BANNED_FUNCTIONS: &[&str] = &[
    "create_storage",
    "save_async",
    "clear_async",
    "load_async",
    "refresh_session",
    "set_session",
    "set_session_async",
    "ensure_authenticated",
    "request_with_timeout",
    "resource_with_timeout",
    "nested_with_timeout",
    "set_password",
    "set_secret",
    "delete_credential",
    // keyring 4.2: `Entry::inner` is the public keyring_core entry, whose attribute update, raw
    // credential (downcast to a backend that deletes whole collections) and the process-wide
    // store setters are not reachable through the read-only `Entry::get_password`.
    "update_attributes",
    "get_credential",
    "as_any",
    "delete_target",
    "set_default_store",
    "unset_default_store",
    "new_with_credential",
    "set_default_credential_builder",
    "remove_file",
    "remove_dir",
    "remove_dir_all",
    "set_permissions",
    "set_modified",
    "set_times",
    "set_len",
];

/// Other names that are always banned. `keyring_core` is the keyring crate's backend layer: its
/// whole API is out of bounds.
const BANNED_IDENTS: &[&str] = &["OpenOptions", "keyring_core"];

/// The only paths through the keyring crate that non-test code may name: building the shared entry
/// and matching the missing-entry error. The one method called on the entry is `get_password`.
const ALLOWED_KEYRING_PATHS: &[&str] = &["keyring::Entry::new", "keyring::Error::NoEntry"];

/// The keyring entry's public field, which exposes the backend entry. Banned where `keyring::` is
/// used.
const KEYRING_ENTRY_FIELD: &str = "inner";

/// Client items that decide which origin receives the session token or hand out the session. Used
/// in [`CLIENT_BUILD_FILE`] only.
const PINNED_CLIENT_ITEMS: &[&str] = &["builder", "base_url", "session"];
const CLIENT_BUILD_FILE: &str = "src/server.rs";
/// The origin override is applied at exactly one place in [`CLIENT_BUILD_FILE`].
const ORIGIN_SETTER: &str = "base_url";

/// rusteero modules that reach below the `Client`. A path through one of them is banned unless it
/// starts with one of the exact [`ALLOWED_RUSTEERO_PATHS`].
const BANNED_RUSTEERO_MODULES: &[&str] = &[
    "api",
    "auth",
    "client",
    "endpoints",
    "routes",
    "storage",
    "transport",
];

/// The only paths through the banned rusteero modules that `src/` may use.
const ALLOWED_RUSTEERO_PATHS: &[&str] = &[
    "rusteero::routes::ApiVersion",
    "rusteero::endpoints::events::CHANNEL_UTILIZATION_BANDS",
    "rusteero::storage::keyring::{ACCOUNT_NAME,SERVICE_NAME}",
    "rusteero::storage::keyring::SERVICE_NAME",
    "rusteero::storage::keyring::ACCOUNT_NAME",
];

/// The only file-system items non-test code may use: reading one regular file, and resolving
/// paths (`canonicalize` is a read: the check that the explicit credential file is not the own
/// file).
const ALLOWED_FS_PATHS: &[&str] = &[
    "fs::read_to_string",
    "fs::metadata",
    "fs::File::open",
    "fs::File",
    "fs::canonicalize",
];

/// The login module: the only file that may name the login and credential-write items below.
const AUTH_FILE: &str = "src/auth.rs";

/// Types that only [`AUTH_FILE`] may name, each with the one path through which it may be used
/// (`Type::item`); a bare mention (an import, a type annotation) is fine there.
const AUTH_CONSTRUCTORS: &[(&str, &str)] = &[
    ("KeyringStore", "KeyringStore::with_entry"),
    ("FileStore", "FileStore::new"),
    ("ChainedStore", "ChainedStore::new"),
    ("LoginFlow", "LoginFlow::with_transport"),
    ("Transport", "Transport::builder"),
    // Taken only as a type, never constructed.
    ("PendingLogin", "PendingLogin"),
    ("CredentialStore", "CredentialStore"),
];

/// Banned functions that [`AUTH_FILE`] may use: the blocking-pool adapters of the stores' save and
/// clear.
const AUTH_ONLY_FUNCTIONS: &[&str] = &["save_async", "clear_async"];

/// The Client's sign-out call: allowed in [`AUTH_FILE`] only.
const AUTH_ONLY_METHODS: &[&str] = &["logout"];

/// The credential stores of [`AUTH_CONSTRUCTORS`]: built, not merely named. Outside an import,
/// every mention must be the one constructor path. A bare mention (an annotation, an alias, a
/// generic argument) would let an inferred `Default` or a factory produce a store without it, and
/// the default keyring store is the shared eero-api entry.
const AUTH_CONSTRUCT_ONLY: &[&str] = &["KeyringStore", "FileStore", "ChainedStore"];

/// The exact arguments (whitespace removed, trailing comma dropped) of the constructors whose
/// arguments decide what is written: the keyring entry's names, the file store's path (always the
/// one the own store holds) and the chained store's two backends.
const AUTH_CONSTRUCTOR_ARGUMENTS: &[(&str, &str)] = &[
    (
        "KeyringStore::with_entry",
        "OWN_KEYRING_SERVICE,OWN_KEYRING_ACCOUNT",
    ),
    ("FileStore::new", "path.clone()"),
    (
        "ChainedStore::new",
        "Arc::clone(keyring),Arc::new(FileStore::new(path.clone()))",
    ),
];

/// Names that `Default` could build a store with: banned in [`AUTH_FILE`] (`default` only when
/// called or reached through a path, `Default` anywhere).
const AUTH_BANNED_DEFAULTS: &[&str] = &["Default", "default"];

/// The login module's public wrappers and the files that may contain each. A name here is banned
/// everywhere else, comments and imports included (every name has an underscore).
const AUTH_WRAPPER_PINS: &[(&str, &[&str])] = &[
    (
        "run_login",
        &[AUTH_FILE, "src/cli.rs", "src/tools/login.rs"],
    ),
    (
        "save_session",
        &[AUTH_FILE, "src/cli.rs", "src/tools/login.rs"],
    ),
    (
        "revoke_replaced",
        &[AUTH_FILE, "src/cli.rs", "src/tools/login.rs"],
    ),
    ("revoke_session", &[AUTH_FILE, "src/cli.rs"]),
    ("sign_out_own_session", &[AUTH_FILE, "src/cli.rs"]),
    ("clear_all", &[AUTH_FILE]),
];

/// The own store's production constructor and the files that may call it.
const OWN_STORE_PRODUCTION_FILES: &[&str] = &[AUTH_FILE, "src/cli.rs", "src/main.rs"];
/// The own store's injectable constructor, for `tests/auth.rs`: defined once in [`AUTH_FILE`],
/// named nowhere else in `src/`.
const OWN_STORE_INJECTABLE: &str = "with_backends";
/// The settings' own session file path: named only by the files that define it, read it for the
/// credential chain and hand it to the store, so no other file can rewrite it (say, to the explicit
/// file's path) before the store is built. Inside [`AUTH_FILE`] it is read once, in one exact form.
const OWN_FILE_SETTING: &str = "own_file";
const OWN_FILE_FILES: &[&str] = &["src/config.rs", "src/credentials.rs", AUTH_FILE];
const OWN_FILE_PREFIX: &str = "settings.";
const OWN_FILE_READ: &str = "settings.own_file.clone()";

/// The rusteero paths [`AUTH_FILE`] may import, each matched exactly (single or grouped): the
/// login flow and pending login live in the flow submodule of rusteero's auth module (its only
/// public path); the transport type comes from rusteero's transport module; the blocking-pool
/// adapters from rusteero's storage module. The store types and the storage error come from the
/// crate root, which the banned-module rule does not touch.
const AUTH_RUSTEERO_PATHS: &[&str] = &[
    "rusteero::auth::flow::LoginFlow",
    "rusteero::auth::flow::PendingLogin",
    "rusteero::transport::Transport",
    "rusteero::storage::save_async",
    "rusteero::storage::clear_async",
];

/// Names [`AUTH_FILE`] may never use, on top of everything banned everywhere: a store load, the
/// shared keyring's constants, eeroctl's file location and the explicit credential file's
/// setting. The own store is written from `src/auth.rs` and read by `src/credentials.rs`; the
/// shared stores and the explicit file are never handed to a writing store.
const AUTH_BANNED_NAMES: &[&str] = &[
    "load",
    // The Client builder: a base URL set on it would decide where the session token goes.
    "client_builder",
    "SERVICE_NAME",
    "ACCOUNT_NAME",
    "session_file",
    "default_session_file",
    "SESSION_FILE_VAR",
    "EEROCTL_CONFIG_DIR_VAR",
    "COOKIES_FILE",
];

/// What the unit-test module of [`AUTH_FILE`] may not name: the guard scans that file whole, so
/// its tests are the pure rules only.
const AUTH_TEST_MODULE_BANNED: &[&str] = &[
    "FileStore",
    "KeyringStore",
    "ChainedStore",
    "CredentialStore",
    "MemoryStore",
    "LoginFlow",
    "PendingLogin",
    "MockServer",
    "wiremock",
    "tempfile",
];

/// The transport builder's two calls, pinned to [`AUTH_FILE`], exactly once each.
const TRANSPORT_PINNED_ITEMS: &[&str] = &["builder", "base_url"];

/// Names that are ordinary English words or generic identifiers on their own: only a call or
/// definition (`name(`) counts, so prose in comments does not trip the guard. Every other banned
/// name contains an underscore and counts anywhere.
fn call_only(name: &str) -> bool {
    !name.contains('_')
}

/// The session-token setter, allowed in this one file only, called exactly once.
const SESSION_SETTER: &str = "set_session_token";
const SESSION_SETTER_FILE: &str = "src/server.rs";
/// The raw API accessor chain, allowed in this one file only, exactly once.
const API_ACCESSOR: &str = "api";
const API_CHAIN: &str = ".api().transport().api_host()";
const API_CHAIN_FILE: &str = "src/ids.rs";

#[derive(Debug, PartialEq, Eq)]
struct Finding {
    file: String,
    line: usize,
    what: String,
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Byte offsets of identifier-boundary occurrences of `name` in `text`.
fn ident_matches(text: &str, name: &str) -> Vec<usize> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(relative) = text[from..].find(name) {
        let start = from + relative;
        let end = start + name.len();
        let before_ok = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_ident(c));
        let after_ok = text[end..].chars().next().is_none_or(|c| !is_ident(c));
        if before_ok && after_ok {
            found.push(start);
        }
        from = end;
    }
    found
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset].matches('\n').count() + 1
}

fn followed_by_paren(text: &str, end: usize) -> bool {
    text[end..].trim_start().starts_with('(')
}

/// Whether the identifier at `offset` (`len` bytes) is used rather than merely mentioned:
/// called (`name(`), called with a turbofish or continued as a path (`name::<T>(`), or reached
/// through a path (`Type::name`), which also covers taking it as a function value
/// (`.then(Client::logout)`, `let f = Client::set_session_token;`).
fn is_used(text: &str, offset: usize, len: usize) -> bool {
    followed_by_paren(text, offset + len)
        || text[offset + len..].trim_start().starts_with("::")
        || text[..offset].trim_end().ends_with("::")
}

/// The path that continues from the identifier at `start`, with whitespace removed: identifiers
/// joined by `::`, and a final `{...}` group. `rusteero :: routes ::\n ApiVersion;` gives
/// `rusteero::routes::ApiVersion`.
fn path_from(text: &str, start: usize) -> String {
    let mut path = String::new();
    let mut rest = &text[start..];
    loop {
        let ident_len = rest.find(|c: char| !is_ident(c)).unwrap_or(rest.len());
        path.push_str(&rest[..ident_len]);
        rest = rest[ident_len..].trim_start();
        let Some(after) = rest.strip_prefix("::") else {
            break;
        };
        path.push_str("::");
        rest = after.trim_start();
        if rest.starts_with('{') {
            let close = rest.find('}').map_or(rest.len(), |i| i + 1);
            path.extend(rest[..close].chars().filter(|c| !c.is_whitespace()));
            break;
        }
    }
    path
}

/// The byte offset of a file's unit-test module: a line that is exactly `#[cfg(test)]` (at column
/// 0, so a comment or a string that merely mentions it does not count) directly followed by a
/// `mod tests` line.
fn test_module_start(text: &str) -> Option<usize> {
    let mut offset = 0;
    let mut lines = text.split_inclusive('\n').peekable();
    while let Some(line) = lines.next() {
        if line.trim_end() == "#[cfg(test)]"
            && lines
                .peek()
                .is_some_and(|next| next.starts_with("mod tests"))
        {
            return Some(offset);
        }
        offset += line.len();
    }
    None
}

/// The part of a source file before its unit-test module (every file here puts its unit tests
/// last; [`scan_test_module_is_last`] enforces it).
fn non_test_part(text: &str) -> &str {
    test_module_start(text).map_or(text, |end| &text[..end])
}

/// Whether `path` is `allowed` or continues it as a longer path (`allowed::...`), not merely a
/// longer name (`keyring::Entry::new_with_target` does not match `keyring::Entry::new`).
fn path_allowed(path: &str, allowed: &str) -> bool {
    path.strip_prefix(allowed)
        .is_some_and(|rest| !rest.starts_with(is_ident))
}

/// Offsets of uses of the Client's raw API accessor, however it is written: `.api(`, `Client::api(`,
/// `Client::api (`, or `Client::api` taken as a function value. An identifier `api` counts when it is
/// called, or reached through `.` or `::`.
fn accessor_uses(text: &str) -> Vec<usize> {
    ident_matches(text, API_ACCESSOR)
        .into_iter()
        .filter(|&offset| {
            let before = text[..offset].trim_end();
            before.ends_with('.')
                || before.ends_with("::")
                || followed_by_paren(text, offset + API_ACCESSOR.len())
        })
        .collect()
}

/// Collects the findings of one file.
struct Report<'a> {
    path: &'a str,
    text: &'a str,
    findings: Vec<Finding>,
}

impl Report<'_> {
    fn at(&mut self, offset: usize, what: String) {
        self.findings.push(Finding {
            file: self.path.to_owned(),
            line: line_of(self.text, offset),
            what,
        });
    }
}

/// Scans one file. `path` is relative to the crate root with `/` separators.
fn scan(path: &str, text: &str) -> Vec<Finding> {
    let mut report = Report {
        path,
        text,
        findings: Vec::new(),
    };
    scan_banned_names(&mut report);
    scan_rusteero_paths(&mut report);
    scan_keyring(&mut report);
    scan_file_writes(&mut report);
    scan_test_module_is_last(&mut report);
    scan_session_setter(&mut report);
    scan_client_construction(&mut report);
    scan_api_accessor(&mut report);
    scan_use_renames(&mut report);
    scan_auth_wrappers(&mut report);
    scan_auth_file(&mut report);
    report.findings
}

/// Whether `name` is one of the items [`AUTH_FILE`] alone may name (and `path` is that file). The
/// constructors and paths of the types are pinned separately by [`scan_auth_file`].
fn auth_exempt(path: &str, name: &str) -> bool {
    path == AUTH_FILE
        && (AUTH_CONSTRUCTORS.iter().any(|(ty, _)| *ty == name)
            || AUTH_ONLY_FUNCTIONS.contains(&name)
            || AUTH_ONLY_METHODS.contains(&name))
}

/// Rusteero methods, credential-store types and the lower-layer functions.
fn scan_banned_names(report: &mut Report<'_>) {
    let text = report.text;
    for name in WRITE_AND_ACTION_METHODS.iter().chain(UNEXPOSED_READS) {
        if auth_exempt(report.path, name) {
            continue;
        }
        for offset in ident_matches(text, name) {
            if call_only(name) && !is_used(text, offset, name.len()) {
                continue;
            }
            report.at(
                offset,
                format!("rusteero method `{name}` is not part of the read-only surface"),
            );
        }
    }
    for name in BANNED_TYPES.iter().chain(BANNED_IDENTS) {
        if auth_exempt(report.path, name) {
            continue;
        }
        for offset in ident_matches(text, name) {
            report.at(
                offset,
                format!(
                    "`{name}`: no credential store, login flow or low-level request type may be named"
                ),
            );
        }
    }
    for name in BANNED_FUNCTIONS {
        if auth_exempt(report.path, name) {
            continue;
        }
        for offset in ident_matches(text, name) {
            report.at(
                offset,
                format!("`{name}` writes, refreshes a session or bypasses the Client"),
            );
        }
    }
}

/// The concrete paths a (possibly grouped) path names: `a::b::{c, d}` is `a::b::c` and `a::b::d`.
/// A path without a group is its own single expansion.
fn expand_group(path_text: &str) -> Vec<String> {
    match path_text.split_once("::{") {
        Some((prefix, group)) => group
            .trim_end_matches('}')
            .split(',')
            .filter(|item| !item.is_empty())
            .map(|item| format!("{prefix}::{item}"))
            .collect(),
        None => vec![path_text.to_owned()],
    }
}

/// Whether `path_text` (every member of a group) is one of the paths `file` may use through a
/// banned rusteero module.
fn rusteero_path_allowed(file: &str, path_text: &str) -> bool {
    expand_group(path_text).iter().all(|path| {
        ALLOWED_RUSTEERO_PATHS
            .iter()
            .any(|allowed| path_allowed(path, allowed))
            || (file == AUTH_FILE
                && AUTH_RUSTEERO_PATHS
                    .iter()
                    .any(|allowed| path_allowed(path, allowed)))
    })
}

/// Paths below the Client (`rusteero::<module>::...`, grouped imports) and `Session::from_env`.
fn scan_rusteero_paths(report: &mut Report<'_>) {
    let text = report.text;
    for offset in ident_matches(text, "rusteero") {
        let path_text = path_from(text, offset);
        if let Some(group) = path_text.strip_prefix("rusteero::{") {
            for item in group.trim_end_matches('}').split(',') {
                let first = item.split("::").next().unwrap_or_default();
                if BANNED_RUSTEERO_MODULES.contains(&first) {
                    report.at(
                        offset,
                        format!("grouped import of the rusteero module `{first}`"),
                    );
                }
            }
            continue;
        }
        let module = path_text
            .strip_prefix("rusteero::")
            .and_then(|rest| rest.split("::").next())
            .unwrap_or_default();
        if BANNED_RUSTEERO_MODULES.contains(&module)
            && !rusteero_path_allowed(report.path, &path_text)
        {
            report.at(
                offset,
                format!("the rusteero module `{module}` reaches below the Client: `{path_text}`"),
            );
        }
    }
    for offset in ident_matches(text, "Session") {
        if path_from(text, offset).starts_with("Session::from_env") {
            report.at(
                offset,
                "`Session::from_env` reads the real process environment".to_owned(),
            );
        }
    }
}

/// The keyring crate outside the unit tests: only the pinned paths, and not the entry's public
/// `inner` handle. (`rusteero::storage::keyring::...` is another crate's path, checked by
/// [`scan_rusteero_paths`].)
fn scan_keyring(report: &mut Report<'_>) {
    let code = non_test_part(report.text);
    let mut uses_crate = false;
    for offset in ident_matches(code, "keyring") {
        if code[..offset].trim_end().ends_with("::") {
            continue;
        }
        let path_text = path_from(code, offset);
        if !path_text.starts_with("keyring::") {
            continue;
        }
        uses_crate = true;
        if !ALLOWED_KEYRING_PATHS
            .iter()
            .any(|allowed| path_allowed(&path_text, allowed))
        {
            report.at(
                offset,
                format!("`{path_text}`: only keyring::Entry::new and keyring::Error::NoEntry may be named"),
            );
        }
    }
    if uses_crate {
        for offset in ident_matches(code, KEYRING_ENTRY_FIELD) {
            report.at(
                offset,
                format!(
                    "`{KEYRING_ENTRY_FIELD}` reaches the keyring backend entry; call get_password only"
                ),
            );
        }
    }
}

/// The unit-test module must be the last item of its file: the file-write scan stops at it, so
/// code placed after it would never be scanned as non-test code. Column-0 lines after the module
/// header may only be its closing brace.
fn scan_test_module_is_last(report: &mut Report<'_>) {
    let Some(start) = test_module_start(report.text) else {
        return;
    };
    let mut offset = start;
    for (index, line) in report.text[start..].split_inclusive('\n').enumerate() {
        let body = line.trim_end();
        if index >= 2 && !body.is_empty() && !body.starts_with([' ', '\t']) && body != "}" {
            report.at(
                offset,
                "code after the unit-test module is not scanned as non-test code".to_owned(),
            );
            return;
        }
        offset += line.len();
    }
}

/// File-system writes outside the unit tests (which use temporary directories), and code the
/// scan could not see.
fn scan_file_writes(report: &mut Report<'_>) {
    let code = non_test_part(report.text);
    for offset in ident_matches(code, "fs") {
        let path_text = path_from(code, offset);
        if path_text.starts_with("fs::")
            && !ALLOWED_FS_PATHS
                .iter()
                .any(|allowed| path_text.starts_with(allowed))
        {
            report.at(
                offset,
                format!("file-system item `{path_text}` is not a plain read"),
            );
        }
    }
    for offset in ident_matches(code, "File") {
        let path_text = path_from(code, offset);
        if path_text.starts_with("File::") && !path_text.starts_with("File::open") {
            report.at(offset, format!("`{path_text}` is not a plain read"));
        }
    }
    let compact: String = report.text.chars().filter(|c| !c.is_whitespace()).collect();
    for hidden in ["include!(", "#[path="] {
        if compact.contains(hidden) {
            report.at(
                0,
                format!("`{hidden}` can pull in code the guard does not scan"),
            );
        }
    }
}

/// The session-token setter: one call, in one file.
fn scan_session_setter(report: &mut Report<'_>) {
    let text = report.text;
    let all = ident_matches(text, SESSION_SETTER);
    if report.path != SESSION_SETTER_FILE {
        for offset in all {
            report.at(
                offset,
                format!("`{SESSION_SETTER}` is allowed in {SESSION_SETTER_FILE} only"),
            );
        }
        return;
    }
    let uses = setter_uses(text);
    if uses.len() > 1 {
        report.at(
            uses[1],
            format!("`{SESSION_SETTER}` may be used exactly once in {SESSION_SETTER_FILE}"),
        );
    }
}

/// Offsets of uses of the session-token setter: calls and function values (`Client::set_session_token`
/// taken without a call, then called any number of times). Prose that names it is not a use.
fn setter_uses(text: &str) -> Vec<usize> {
    ident_matches(text, SESSION_SETTER)
        .into_iter()
        .filter(|&offset| is_used(text, offset, SESSION_SETTER.len()))
        .collect()
}

/// Building a Client and reading its session: `Client::builder`, the origin override and the
/// `session` accessor and builder setter are used in one file only, where the origin override is
/// applied exactly once. A handler that built a second Client, or handed the session to one, could
/// send the token to an origin the configuration never allowed.
fn scan_client_construction(report: &mut Report<'_>) {
    let text = report.text;
    for name in PINNED_CLIENT_ITEMS {
        let uses: Vec<usize> = ident_matches(text, name)
            .into_iter()
            .filter(|&offset| is_used(text, offset, name.len()))
            .collect();
        if report.path == CLIENT_BUILD_FILE {
            if *name == ORIGIN_SETTER && uses.len() > 1 {
                report.at(
                    uses[1],
                    format!("`{name}` may be applied exactly once in {CLIENT_BUILD_FILE}"),
                );
            }
        } else if report.path == AUTH_FILE && TRANSPORT_PINNED_ITEMS.contains(name) {
            // The login flow's transport builder: its builder call and base URL, once each.
            if uses.len() > 1 {
                report.at(
                    uses[1],
                    format!(
                        "`{name}` may be used exactly once in {AUTH_FILE} (the login transport)"
                    ),
                );
            }
        } else {
            for offset in uses {
                report.at(
                    offset,
                    format!(
                        "`{name}` decides where the session token goes; it is allowed in \
                         {CLIENT_BUILD_FILE} only"
                    ),
                );
            }
        }
    }
}

/// The raw API accessor: one pinned chain, in one file, once. Whitespace is ignored for the chain
/// so that rustfmt line breaks inside it are fine.
fn scan_api_accessor(report: &mut Report<'_>) {
    let accessors = accessor_uses(report.text);
    if accessors.is_empty() {
        return;
    }
    if report.path != API_CHAIN_FILE {
        report.at(
            accessors[0],
            format!("the raw API accessor is allowed in {API_CHAIN_FILE} only"),
        );
        return;
    }
    let compact: String = report.text.chars().filter(|c| !c.is_whitespace()).collect();
    let chains = compact.matches(API_CHAIN).count();
    if accessors.len() != 1 || chains != 1 {
        report.at(
            accessors[0],
            format!(
                "expected the chain `{API_CHAIN}` exactly once and no other use of the accessor, \
                 found {} accessor use(s) and {chains} chain(s)",
                accessors.len()
            ),
        );
    }
}

/// The text with all whitespace removed.
fn compact(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Byte ranges of the file's `use` statements. A statement starts on a line that begins (after
/// indentation and an optional visibility) with `use ` and ends at the next semicolon. A line that
/// merely starts with the word inside a comment or a string is not one: a candidate whose text up
/// to the semicolon holds a quote or a comment marker is rejected, so it cannot hide the code
/// after it.
fn use_statements(text: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let rest = ["pub(crate) ", "pub(super) ", "pub "]
            .iter()
            .find_map(|visibility| trimmed.strip_prefix(visibility))
            .unwrap_or(trimmed);
        if rest.starts_with("use ") {
            let start = offset + (line.len() - trimmed.len());
            let end = text[start..]
                .find(';')
                .map_or(text.len(), |semicolon| start + semicolon + 1);
            let statement = &text[start..end];
            if !statement.contains(['"', '\'']) && !statement.contains("//") {
                ranges.push((start, end));
            }
        }
        offset += line.len();
    }
    ranges
}

fn in_ranges(ranges: &[(usize, usize)], offset: usize) -> bool {
    ranges
        .iter()
        .any(|&(start, end)| (start..end).contains(&offset))
}

/// Whether the word right before `offset` (whitespace aside) is exactly `word`.
fn preceded_by_word(text: &str, offset: usize, word: &str) -> bool {
    text[..offset]
        .trim_end()
        .strip_suffix(word)
        .is_some_and(|rest| rest.chars().next_back().is_none_or(|c| !is_ident(c)))
}

/// The arguments of the call `path(...)` that starts at `offset`, whitespace removed and a
/// trailing comma dropped. `None` when the path is not directly followed by a call (a function
/// value, say). Comments inside the parentheses stay in the text, so they never match.
fn compact_call_arguments(text: &str, offset: usize, path: &str) -> Option<String> {
    let flat = compact(&text[offset..]);
    let rest = flat.strip_prefix(path)?.strip_prefix('(')?;
    let mut depth = 1usize;
    for (index, c) in rest.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(rest[..index].trim_end_matches(',').to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

/// An import from rusteero may not rename what it brings in: every rule here is by name.
fn scan_use_renames(report: &mut Report<'_>) {
    let text = report.text;
    for (start, end) in use_statements(text) {
        let statement = &text[start..end];
        if !ident_matches(statement, "rusteero").is_empty()
            && !ident_matches(statement, "as").is_empty()
        {
            report.at(
                start,
                "an import from rusteero may not be renamed (`as`): the name-based rules would stop seeing the item"
                    .to_owned(),
            );
        }
    }
}

/// The login module's public wrappers, pinned to the files that need them, and the own store's two
/// constructors. The store's fields are private, so a value is built only by these.
fn scan_auth_wrappers(report: &mut Report<'_>) {
    let text = report.text;
    for (name, files) in AUTH_WRAPPER_PINS {
        if files.contains(&report.path) {
            continue;
        }
        for offset in ident_matches(text, name) {
            report.at(
                offset,
                format!("`{name}` is allowed in {} only", files.join(", ")),
            );
        }
    }
    let production_allowed = OWN_STORE_PRODUCTION_FILES.contains(&report.path);
    for offset in ident_matches(text, "OwnStore") {
        let path_text = path_from(text, offset);
        let Some(item) = path_text.strip_prefix("OwnStore::") else {
            continue;
        };
        let item: String = item.chars().take_while(|c| is_ident(*c)).collect();
        if item == "production" && production_allowed {
            continue;
        }
        report.at(
            offset,
            format!(
                "`OwnStore::{item}`: the own store is built by `OwnStore::production` only, in {}",
                OWN_STORE_PRODUCTION_FILES.join(", ")
            ),
        );
    }
    if !production_allowed {
        for offset in ident_matches(text, "production") {
            if text[..offset].trim_end().ends_with("::") {
                report.at(
                    offset,
                    format!(
                        "`production` reached through a path: the own store is built in {} only",
                        OWN_STORE_PRODUCTION_FILES.join(", ")
                    ),
                );
            }
        }
    }
    if !OWN_FILE_FILES.contains(&report.path) {
        for offset in ident_matches(text, OWN_FILE_SETTING) {
            report.at(
                offset,
                format!(
                    "`{OWN_FILE_SETTING}` is named in {} only",
                    OWN_FILE_FILES.join(", ")
                ),
            );
        }
    }
    // The injectable constructor: its definition, once, in the login module.
    for (index, offset) in ident_matches(text, OWN_STORE_INJECTABLE)
        .into_iter()
        .enumerate()
    {
        let definition =
            report.path == AUTH_FILE && index == 0 && preceded_by_word(text, offset, "fn");
        if !definition {
            report.at(
                offset,
                format!(
                    "`{OWN_STORE_INJECTABLE}` may only be defined, once, in {AUTH_FILE}; it is for tests/auth.rs"
                ),
            );
        }
    }
}

/// The login module's own pins: each store, the login flow and the transport only through their
/// one constructor, with pinned arguments (an import may name them; nothing else may, so no
/// annotation, alias or inferred `Default` can build one); the keyring store only with eero-mcp's
/// own names; the own file's path only from the settings' own-file setting; no `Default`; and none
/// of the names that would let it touch a shared or explicit credential, load a store, or use the
/// in-memory store in its unit tests.
fn scan_auth_file(report: &mut Report<'_>) {
    if report.path != AUTH_FILE {
        return;
    }
    scan_auth_constructors(report);
    let text = report.text;
    // The builder call must be the transport's, never the Client's.
    for offset in ident_matches(text, "builder") {
        if is_used(text, offset, "builder".len())
            && !text[..offset].trim_end().ends_with("Transport::")
        {
            report.at(
                offset,
                format!("`builder` in {AUTH_FILE} may be `Transport::builder` only"),
            );
        }
    }
    for name in AUTH_BANNED_NAMES {
        for offset in ident_matches(text, name) {
            if call_only(name) && !is_used(text, offset, name.len()) {
                continue;
            }
            report.at(
                offset,
                format!("`{name}` is not allowed in {AUTH_FILE}: it would load a store, or reach a shared or explicit credential"),
            );
        }
    }
    for name in AUTH_BANNED_DEFAULTS {
        for offset in ident_matches(text, name) {
            // The lower-case word is prose unless it is called or reached through a path.
            if *name == "default" && !is_used(text, offset, name.len()) {
                continue;
            }
            report.at(
                offset,
                format!("`{name}` is not allowed in {AUTH_FILE}: the default of a store is the shared credential"),
            );
        }
    }
    scan_own_file_read(report);
    if let Some(start) = test_module_start(text) {
        for name in AUTH_TEST_MODULE_BANNED {
            for offset in ident_matches(&text[start..], name) {
                report.at(
                    start + offset,
                    format!("`{name}` in the unit tests of {AUTH_FILE}: those tests belong in tests/auth.rs"),
                );
            }
        }
    }
}

/// The stores, the login flow and the transport in [`AUTH_FILE`]: the store types only through
/// their one constructor (or in an import), the other types only as their pinned path, and the
/// constructors that decide what is written with exactly the pinned arguments.
fn scan_auth_constructors(report: &mut Report<'_>) {
    let text = report.text;
    let uses = use_statements(text);
    for (ty, allowed) in AUTH_CONSTRUCTORS {
        let construct_only = AUTH_CONSTRUCT_ONLY.contains(ty);
        for offset in ident_matches(text, ty) {
            let path_text = path_from(text, offset);
            if construct_only {
                if !in_ranges(&uses, offset) && !path_allowed(&path_text, allowed) {
                    report.at(
                        offset,
                        format!(
                            "`{ty}`: {AUTH_FILE} may name it in an import or as `{allowed}(...)` only, not as `{path_text}`"
                        ),
                    );
                }
            } else if path_text.starts_with(&format!("{ty}::"))
                && !path_allowed(&path_text, allowed)
            {
                report.at(
                    offset,
                    format!("`{path_text}`: {AUTH_FILE} may use `{allowed}` only"),
                );
            }
        }
    }
    for (path, expected) in AUTH_CONSTRUCTOR_ARGUMENTS {
        let ty = path.split("::").next().unwrap_or_default();
        for offset in ident_matches(text, ty) {
            if in_ranges(&uses, offset) || !path_allowed(&path_from(text, offset), path) {
                continue;
            }
            if compact_call_arguments(text, offset, path).as_deref() != Some(expected) {
                report.at(
                    offset,
                    format!("`{path}` must be called with exactly `{expected}`"),
                );
            }
        }
    }
}

/// The own file's path reaches the store from the settings' own-file setting, read once.
fn scan_own_file_read(report: &mut Report<'_>) {
    let text = report.text;
    for (index, offset) in ident_matches(text, OWN_FILE_SETTING)
        .into_iter()
        .enumerate()
    {
        let before: String = text[..offset]
            .chars()
            .rev()
            .filter(|c| !c.is_whitespace())
            .take(OWN_FILE_PREFIX.len())
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let exact =
            before == OWN_FILE_PREFIX && compact(&text[offset..]).starts_with("own_file.clone()");
        if index > 0 || !exact {
            report.at(
                offset,
                format!("the own file's path is read once, as `{OWN_FILE_READ}`, in {AUTH_FILE}"),
            );
        }
    }
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn scan_src_tree() -> (Vec<Finding>, Vec<String>) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    let mut findings = Vec::new();
    let mut scanned = Vec::new();
    for file in files {
        let relative = file
            .strip_prefix(&root)
            .expect("under the crate root")
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(&file).unwrap_or_else(|e| panic!("{relative}: {e}"));
        findings.extend(scan(&relative, &text));
        scanned.push(relative);
    }
    (findings, scanned)
}

// ===================== the guard over the real source =====================

#[test]
fn src_names_no_write_action_session_or_store_item() {
    let (findings, scanned) = scan_src_tree();
    assert!(
        scanned.len() >= 15,
        "the scan found the source tree: {scanned:?}"
    );
    for required in [
        "src/ids.rs",
        "src/server.rs",
        "src/tools/account.rs",
        "src/main.rs",
        "src/credentials.rs",
    ] {
        assert!(
            scanned.iter().any(|f| f == required),
            "{required} was scanned"
        );
    }
    assert!(
        findings.is_empty(),
        "the read-only guard found:\n{}",
        findings
            .iter()
            .map(|f| format!("  {}:{}: {}", f.file, f.line, f.what))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn both_pinned_exceptions_exist_where_they_are_allowed() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let server = fs::read_to_string(root.join(SESSION_SETTER_FILE)).expect("server.rs");
    // One use: the credential re-read. (Doc comments may name the method; a use is a call, however
    // it is qualified, or a function value.)
    assert_eq!(
        setter_uses(&server).len(),
        1,
        "the session-token setter is used exactly once in {SESSION_SETTER_FILE}"
    );
    let uses_of = |name: &str| {
        ident_matches(&server, name)
            .into_iter()
            .filter(|&offset| is_used(&server, offset, name.len()))
            .count()
    };
    assert_eq!(
        uses_of(ORIGIN_SETTER),
        1,
        "the origin override is applied exactly once in {CLIENT_BUILD_FILE}"
    );
    assert!(
        uses_of("builder") >= 1 && uses_of("session") >= 1,
        "the Client is built and its session read in {CLIENT_BUILD_FILE}"
    );
    // The login module's pins: one transport builder call, one base URL, the Client's sign-out,
    // and the keyring store only with eero-mcp's own names.
    let auth = fs::read_to_string(root.join(AUTH_FILE)).expect("auth.rs");
    let auth_uses = |name: &str| {
        ident_matches(&auth, name)
            .into_iter()
            .filter(|&offset| is_used(&auth, offset, name.len()))
            .count()
    };
    for name in TRANSPORT_PINNED_ITEMS {
        assert_eq!(
            auth_uses(name),
            1,
            "`{name}` (the login transport) is used exactly once in {AUTH_FILE}"
        );
    }
    assert!(
        auth_uses("logout") >= 1,
        "the Client's sign-out is called in {AUTH_FILE}, the only place it may be"
    );
    assert!(
        auth_uses("with_entry") >= 1,
        "{AUTH_FILE} builds the own keyring store"
    );
    // The own store gets its file path from the settings once, and its injectable constructor is
    // defined once (the scan above fails any other mention).
    assert_eq!(
        compact(&auth).matches(OWN_FILE_READ).count(),
        1,
        "{AUTH_FILE} reads the settings' own file path exactly once"
    );
    assert_eq!(
        ident_matches(&auth, OWN_STORE_INJECTABLE).len(),
        1,
        "the injectable constructor is defined once in {AUTH_FILE}"
    );
    let ids = fs::read_to_string(root.join(API_CHAIN_FILE)).expect("ids.rs");
    let compact: String = ids.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(
        compact.matches(API_CHAIN).count(),
        1,
        "the API host is read through the pinned chain exactly once in {API_CHAIN_FILE}"
    );
    assert_eq!(
        accessor_uses(&ids).len(),
        1,
        "and the accessor is used nowhere else in {API_CHAIN_FILE}"
    );
}

// ===================== the lists =====================

#[test]
fn the_lists_are_consistent() {
    let mut all: Vec<&str> = Vec::new();
    all.extend(WRITE_AND_ACTION_METHODS);
    all.extend(UNEXPOSED_READS);
    all.extend(CATALOGUE_READS);
    all.extend(ALLOWED_CLIENT_ITEMS);
    let mut sorted = all.clone();
    sorted.sort_unstable();
    let before = sorted.len();
    sorted.dedup();
    assert_eq!(
        before,
        sorted.len(),
        "no name appears in two lists or twice"
    );
    assert_eq!(CATALOGUE_READS.len(), 40);
    assert_eq!(
        CATALOGUE_READS.len() + UNEXPOSED_READS.len(),
        78,
        "rusteero 3.0.x has 78 reads"
    );
    assert_eq!(ALLOWED_CLIENT_ITEMS.len(), 15);
    for read in CATALOGUE_READS.iter().chain(UNEXPOSED_READS) {
        assert!(
            ["get_", "list_", "has_", "discover_"]
                .iter()
                .any(|p| read.starts_with(p)),
            "{read} is a read"
        );
    }
    for name in WRITE_AND_ACTION_METHODS {
        assert!(
            !["get_", "list_", "has_", "discover_"]
                .iter()
                .any(|p| name.starts_with(p)),
            "{name} is not a read"
        );
    }
}

#[test]
fn the_lists_name_every_family_the_task_requires() {
    for required in [
        "clear_cache",
        "set_preferred_network",
        "logout",
        "clear_session_token",
        "clear_auth_data",
        "http_builder",
        "store",
        "set_dhcp",
        "set_sqm",
        "create_forward",
        "update_schedule",
        "delete_profile",
        "run_speed_test",
        "run_diagnostics",
        "reboot_eero",
        "reboot_network",
        "block_device",
        "unblock_device",
        "pause_device",
        "pause_profile",
        "apply_update",
        "mark_notifications_read",
        "regenerate_thread_credentials",
        "request_support",
        "create_burst_reporter",
        "start_backup_ssid_discovery",
    ] {
        assert!(
            WRITE_AND_ACTION_METHODS.contains(&required),
            "{required} is banned"
        );
    }
    for prefix in ["set_", "create_", "update_", "delete_"] {
        assert!(
            WRITE_AND_ACTION_METHODS
                .iter()
                .filter(|n| n.starts_with(prefix))
                .count()
                >= 5,
            "{prefix}* families are banned"
        );
    }
    assert!(
        !WRITE_AND_ACTION_METHODS.contains(&SESSION_SETTER),
        "the session setter is checked at its pinned site instead"
    );
}

/// The public functions of `src/client/*.rs` in the rusteero checkout that this crate builds
/// against, found through `cargo metadata` so a version bump is noticed.
fn rusteero_client_functions() -> BTreeSet<String> {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked", "--offline"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata starts");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata prints JSON");
    let manifest = metadata["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .find(|package| package["name"] == "rusteero")
        .and_then(|package| package["manifest_path"].as_str())
        .expect("rusteero is in the dependency graph");
    let client_dir = Path::new(manifest)
        .parent()
        .expect("manifest directory")
        .join("src")
        .join("client");

    let mut functions = BTreeSet::new();
    for entry in fs::read_dir(&client_dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", client_dir.display()))
    {
        let path = entry.expect("dir entry").path();
        if path.extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("rusteero source");
        for line in source.lines() {
            let line = line.trim_start();
            let Some(rest) = line
                .strip_prefix("pub async fn ")
                .or_else(|| line.strip_prefix("pub fn "))
            else {
                continue;
            };
            let name: String = rest.chars().take_while(|c| is_ident(*c)).collect();
            functions.insert(name);
        }
    }
    functions
}

#[test]
fn every_public_client_function_is_classified() {
    let found = rusteero_client_functions();
    let classified: BTreeSet<String> = WRITE_AND_ACTION_METHODS
        .iter()
        .chain(UNEXPOSED_READS)
        .chain(CATALOGUE_READS)
        .chain(ALLOWED_CLIENT_ITEMS)
        .map(|name| (*name).to_owned())
        .collect();
    let unclassified: Vec<&String> = found.difference(&classified).collect();
    assert!(
        unclassified.is_empty(),
        "rusteero has public Client/ClientBuilder functions this guard has never seen. Classify \
         each one as a catalogue read, an unexposed read, a write/action, or an allowed accessor: \
         {unclassified:?}"
    );
    let stale: Vec<&String> = classified.difference(&found).collect();
    assert!(
        stale.is_empty(),
        "the guard lists functions rusteero no longer has; remove them: {stale:?}"
    );
}

// ===================== the matcher itself =====================

fn findings(path: &str, text: &str) -> Vec<String> {
    scan(path, text).into_iter().map(|f| f.what).collect()
}

#[test]
fn write_and_action_names_are_found_in_code_and_in_comments() {
    assert!(!findings("src/x.rs", "client.set_dhcp(true).await;").is_empty());
    assert!(!findings("src/x.rs", "// never call reboot_eero here").is_empty());
    assert!(!findings("src/x.rs", "/// see `clear_cache`").is_empty());
    assert!(!findings("src/x.rs", "let f = Client::block_device;").is_empty());
    assert!(
        !findings("src/x.rs", "c.get_sms_countries().await").is_empty(),
        "unexposed read"
    );
    assert!(!findings("src/x.rs", "use rusteero::FileStore;").is_empty());
    assert!(!findings("src/x.rs", "KeyringStore::new()").is_empty());
}

#[test]
fn matching_respects_identifier_boundaries() {
    for harmless in [
        "let restored = 1;",
        "fn is_blocked() {}",
        "let paused_state = 2;",
        "fn runs_diagnostics_summary() {}",
        "let set_dhcp_ok = 1;",
        "let my_set_dhcp = 1;",
        "get_account(refresh)",
        "c.get_devices(Some(net), refresh, None, None)",
        "let get_retries = 1;",
        "let api_base_url = 1;",
        "fn api_host() {}",
        "let transport_ok = 1;",
        "settings.set_session_file()",
    ] {
        assert_eq!(
            findings("src/x.rs", harmless),
            Vec::<String>::new(),
            "{harmless}"
        );
    }
}

#[test]
fn single_word_names_count_only_as_calls() {
    // `store` and `logout` are ordinary words: prose is fine, a call is not.
    assert!(
        findings(
            "src/x.rs",
            "// no credential store is attached; logout never runs"
        )
        .is_empty()
    );
    assert!(!findings("src/x.rs", "builder.store(Some(x))").is_empty());
    assert!(!findings("src/x.rs", "client.logout().await").is_empty());
    assert!(!findings("src/x.rs", "client.store (x)").is_empty());
}

#[test]
fn single_word_names_are_caught_as_function_values_and_with_a_turbofish() {
    for sneaky in [
        "let f = Client::logout;",
        "let f = rusteero::Client::logout;",
        "let f = <Client>::logout;",
        "let f = Client\n    ::logout;",
        "maybe.then(Client::logout)",
        "b.map(ClientBuilder::store)",
        "let s = ClientBuilder::store;",
        "builder.store::<Store>(x)",
        "client.logout::<()>()",
    ] {
        assert!(!findings("src/x.rs", sneaky).is_empty(), "{sneaky}");
    }
    // Prose, and ordinary identifiers that happen to contain the words, stay fine.
    for fine in [
        "// logout is never called; no store is attached",
        "/// the credential store: see the logout docs.",
        "let restore = 1; let logouts = 2;",
        "let store_ok = true;",
    ] {
        assert_eq!(findings("src/x.rs", fine), Vec::<String>::new(), "{fine}");
    }
}

#[test]
fn the_session_setter_is_allowed_in_server_rs_only_and_once() {
    let code = "client.set_session_token(token).await";
    assert!(findings("src/server.rs", code).is_empty());
    assert!(!findings("src/ids.rs", code).is_empty());
    assert!(!findings("src/tools/account.rs", code).is_empty());
    assert!(!findings("src/credentials.rs", "// set_session_token").is_empty());
    // A second call in server.rs, however it is written.
    assert!(!findings("src/server.rs", &format!("{code}; {code}")).is_empty());
    assert!(
        !findings(
            "src/server.rs",
            &format!("{code}; Client::set_session_token(&c, t).await")
        )
        .is_empty()
    );
    assert!(
        !findings(
            "src/server.rs",
            &format!("{code}; rusteero::Client::set_session_token (&c, t)")
        )
        .is_empty()
    );
    // Prose naming it is not a call.
    assert!(
        findings(
            "src/server.rs",
            &format!("// calls set_session_token once\n{code}")
        )
        .is_empty()
    );
}

#[test]
fn the_session_setter_taken_as_a_function_value_counts_as_a_use() {
    let code = "client.set_session_token(token).await";
    // Taking it as a value, then calling the value any number of times, is a second use.
    for value in [
        "let install = Client::set_session_token;",
        "let install = rusteero::Client::set_session_token;",
        "let install = <Client>::set_session_token;",
        "let install = Client::set_session_token::<>;",
    ] {
        assert!(
            !findings("src/server.rs", &format!("{code}; {value}")).is_empty(),
            "{value}"
        );
        assert!(!findings("src/ids.rs", value).is_empty(), "{value}");
    }
    // The value alone is one use, which is the allowed count.
    assert!(
        findings(
            "src/server.rs",
            "let install = Client::set_session_token; install(&c, t).await;"
        )
        .is_empty()
    );
    assert_eq!(
        setter_uses("// set_session_token\nlet i = Client::set_session_token;").len(),
        1
    );
}

#[test]
fn the_api_accessor_is_allowed_as_one_exact_chain_in_ids_rs_only() {
    let chain = "Self { host: client.api().transport().api_host() }";
    assert!(findings("src/ids.rs", chain).is_empty());
    // rustfmt may break the chain across lines.
    let broken = "client\n    .api()\n    .transport()\n    .api_host()";
    assert!(findings("src/ids.rs", broken).is_empty());
    // Anywhere else.
    assert!(!findings("src/server.rs", chain).is_empty());
    assert!(!findings("src/tools/devices.rs", chain).is_empty());
    // Any other use in ids.rs, or a second use, or a different chain.
    assert!(!findings("src/ids.rs", "client.api().auth()").is_empty());
    assert!(!findings("src/ids.rs", "client.api().transport().request()").is_empty());
    assert!(!findings("src/ids.rs", &format!("{chain}; {chain}")).is_empty());
    assert!(!findings("src/ids.rs", &format!("{chain}; client.api().devices()")).is_empty());
    // A mention of the accessor in prose is not a call.
    assert!(findings("src/ids.rs", "// the raw API accessor is used once").is_empty());
}

#[test]
fn the_api_accessor_is_caught_in_every_call_syntax() {
    for sneaky in [
        "let t = rusteero::Client::api(&client).transport();",
        "let t = Client::api (&client);",
        "let t = <Client>::api(&client);",
        "let f = Client::api;",
        "let t = client\n    .api ();",
        "let t = (&client).api();",
    ] {
        assert!(
            !findings("src/tools/devices.rs", sneaky).is_empty(),
            "{sneaky}"
        );
        assert!(!findings("src/server.rs", sneaky).is_empty(), "{sneaky}");
    }
    // In ids.rs only the pinned chain passes: a path-call is a second use.
    let chain = "client.api().transport().api_host()";
    assert!(!findings("src/ids.rs", &format!("{chain}; Client::api(&c)")).is_empty());
    assert!(!findings("src/ids.rs", "Client::api(&c).transport().api_host()").is_empty());
}

#[test]
fn lower_layers_that_bypass_the_client_are_banned() {
    for sneaky in [
        "let t = Transport::builder().build()?;",
        "use rusteero::transport::Transport;",
        "use rusteero::{Client, transport::Transport};",
        "t.refresh_session().await?;",
        "t.set_session_async(None).await?;",
        "t.request_with_timeout(a, b, c).await",
        "use rusteero::api::AuthApi;",
        "rusteero::routes::networks::REBOOT_NETWORK_V8",
        "use rusteero::routes::{ApiVersion, networks};",
        "use rusteero::endpoints::networks::NetworksApi;",
        "rusteero::endpoints::events::OTHER_CONSTANT",
        "rusteero::storage::create_storage(&config)",
        "use rusteero::storage::StorageConfig;",
        "clear_async(store).await",
        "save_async(store, session).await",
        "let s = rusteero::Session::from_env(\"RUSTEERO_SESSION_TOKEN\");",
        "let s = Session::from_env (\"X\");",
        "client.ensure_authenticated().await",
        "let b = RequestBody::EmptyJsonString;",
    ] {
        assert!(!findings("src/x.rs", sneaky).is_empty(), "{sneaky}");
    }
    // The exceptions the crate really uses.
    for fine in [
        "use rusteero::routes::ApiVersion;",
        "rusteero::routes::ApiVersion::V2_2",
        "rusteero::endpoints::events::CHANNEL_UTILIZATION_BANDS",
        "use rusteero::storage::keyring::{ACCOUNT_NAME, SERVICE_NAME};",
        "use rusteero::{Client, ClientBuilder, Envelope, Error, Session};",
        "use rusteero::links::validate_identifier;",
        "use rusteero::params::resolve_nested_url;",
        "rusteero::resource_url(host, value, template, ApiVersion::V2_2)",
        "let s = Settings::from_env(&env);",
        "use rmcp::transport::stdio;",
    ] {
        assert_eq!(findings("src/x.rs", fine), Vec::<String>::new(), "{fine}");
    }
}

#[test]
fn credential_and_file_writes_are_banned_outside_unit_tests() {
    for sneaky in [
        "entry.set_password(\"x\")?;",
        "entry.set_secret(b\"x\")?;",
        "entry.delete_credential()?;",
        "std::fs::write(path, data)?;",
        "fs::write(path, data)?;",
        "std::fs::remove_file(path)?;",
        "std::fs::rename(a, b)?;",
        "std::fs::{self, write}",
        "let f = std::fs::File::create(path)?;",
        "let f = File::create_new(path)?;",
        "let f = File::options().append(true).open(p)?;",
        "OpenOptions::new().write(true).open(p)?",
        "tokio::fs::write(path, data).await?;",
        "include!(\"elsewhere.rs\");",
        "#[path = \"elsewhere.rs\"] mod elsewhere;",
        // Calls on an open handle that change the file although it was opened read-only.
        "file.set_permissions(perms)?;",
        "file.set_modified(time)?;",
        "file.set_times(times)?;",
        "file.set_len(0)?;",
        "std::fs::set_permissions(path, perms)?;",
    ] {
        assert!(!findings("src/x.rs", sneaky).is_empty(), "{sneaky}");
    }
    for fine in [
        "std::fs::read_to_string(path)",
        "let meta = std::fs::metadata(path)?;",
        "let file = std::fs::File::open(path)?;",
        "use std::fs::File;",
    ] {
        assert_eq!(findings("src/x.rs", fine), Vec::<String>::new(), "{fine}");
    }
    // Unit tests may use temporary directories.
    let with_test = "fn f() {}\n#[cfg(test)]\nmod tests { fn t() { std::fs::write(p, d); } }";
    assert_eq!(findings("src/x.rs", with_test), Vec::<String>::new());
    // The ban on the keyring write calls holds in test code too.
    assert!(
        !findings(
            "src/x.rs",
            "fn f() {}\n#[cfg(test)]\nmod t { fn x() { e.set_password(p); } }"
        )
        .is_empty()
    );
}

#[test]
fn the_keyring_crate_is_limited_to_one_entry_read() {
    // What credentials.rs does.
    let fine = "use rusteero::storage::keyring::{ACCOUNT_NAME, SERVICE_NAME};\n\
                let Ok(entry) = keyring::Entry::new(SERVICE_NAME, ACCOUNT_NAME) else { return };\n\
                match entry.get_password() { Err(keyring::Error::NoEntry) => {}, _ => {} }";
    assert_eq!(findings("src/credentials.rs", fine), Vec::<String>::new());
    // Anything else the crate offers, however it is reached.
    for sneaky in [
        "use keyring::Entry;",
        "use keyring::{Entry, Error};",
        "keyring::Entry::new_with_target(t, s, u)",
        "keyring::Error::Invalid(a, b)",
        "keyring::v1::Entry::new(s, u)",
        "let handle = &entry.inner;",
        "let keyring::Entry { inner } = entry;",
        "entry.inner.update_attributes(&attrs)?;",
        "entry.inner.get_credential().as_any()",
        "keyring_core::set_default_store(store)",
        "keyring_core::unset_default_store()",
        "keyring_core::Entry::new_with_credential(c)",
        "wrapper.delete_target()",
        "keyring::Entry::new(s, u)?.set_default_credential_builder(b)",
    ] {
        assert!(
            !findings(
                "src/credentials.rs",
                &format!("let _ = keyring::Entry::new(s, u);\n{sneaky}")
            )
            .is_empty(),
            "{sneaky}"
        );
    }
    // `inner` is an ordinary identifier where the keyring crate is not used.
    assert_eq!(
        findings("src/errors.rs", "let inner = value[\"error\"].as_object();"),
        Vec::<String>::new()
    );
}

#[test]
fn a_mention_of_the_test_attribute_does_not_hide_the_rest_of_the_file() {
    // The old scan cut at the first literal `#[cfg(test)]` anywhere, comments and strings included.
    for mention in [
        "// the unit tests sit behind #[cfg(test)]\n",
        "/// see `#[cfg(test)]`\n",
        "const NOTE: &str = \"#[cfg(test)]\";\n",
        "    #[cfg(test)]\n",
        "#[cfg(test)]\nfn helper() {}\n",
    ] {
        let source = format!("{mention}fn f() {{ std::fs::write(p, d); }}\n");
        assert!(
            !findings("src/x.rs", &source).is_empty(),
            "a file write after {mention:?} is still found"
        );
    }
    // The real shape still exempts the unit tests.
    let source = "fn f() {}\n#[cfg(test)]\nmod tests {\n    fn t() { std::fs::write(p, d); }\n}\n";
    assert_eq!(findings("src/x.rs", source), Vec::<String>::new());
}

#[test]
fn the_unit_test_module_must_be_the_last_item() {
    let after = "fn f() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\nfn g() { std::fs::write(p, d); }\n";
    let found = findings("src/x.rs", after);
    assert!(
        found
            .iter()
            .any(|what| what.contains("after the unit-test module")),
        "{found:?}"
    );
    let comment_after = "fn f() {}\n#[cfg(test)]\nmod tests {\n}\n// trailing note\n";
    assert!(!findings("src/x.rs", comment_after).is_empty());
    let last = "fn f() {}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn t() {}\n}\n";
    assert_eq!(findings("src/x.rs", last), Vec::<String>::new());
}

#[test]
fn client_construction_and_the_session_accessor_are_pinned_to_server_rs() {
    let build = "let mut b = Client::builder().get_retries(1);\n\
                 b = b.base_url(url);\n\
                 b.session(token)";
    assert_eq!(findings("src/server.rs", build), Vec::<String>::new());
    let accessor = "client.session().filter(Session::is_valid)";
    assert_eq!(findings("src/server.rs", accessor), Vec::<String>::new());
    for sneaky in [
        "Client::builder().build().await",
        "rusteero::Client::builder()",
        "let b = ClientBuilder::base_url;",
        "Client::builder().base_url(agent_url).session(self.shared.client.session()).build()",
        "self.shared.client.session()",
        "builder.session(s)",
        "b.base_url(u)",
        "Client::builder::<>()",
    ] {
        assert!(
            !findings("src/tools/devices.rs", sneaky).is_empty(),
            "{sneaky}"
        );
        assert!(!findings("src/main.rs", sneaky).is_empty(), "{sneaky}");
    }
    // The origin override is applied once, even in server.rs.
    let twice = "b.base_url(url); b.base_url(other);";
    assert!(!findings("src/server.rs", twice).is_empty());
    // Ordinary words and other crates' builders are not Client construction.
    for fine in [
        "tokio::runtime::Builder::new_multi_thread().enable_all().build()",
        "let session = Session::from_json(record)?; session.token()",
        "settings.api_base_url.as_deref()",
        "\"error.session.expired\"",
        "// the builder sets the base_url for the session",
        "ServerCapabilities::default()",
    ] {
        assert_eq!(
            findings("src/credentials.rs", fine),
            Vec::<String>::new(),
            "{fine}"
        );
    }
}

#[test]
fn findings_carry_file_and_line() {
    let found = scan("src/x.rs", "line one\nline two\nclient.set_dns_mode(x);\n");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].file, "src/x.rs");
    assert_eq!(found[0].line, 3);
}

// ===================== the login module =====================

/// Snippets only `src/auth.rs` may contain, each as it appears in that file.
const AUTH_ONLY_SNIPPETS: &[&str] = &[
    "use rusteero::auth::flow::{LoginFlow, PendingLogin};",
    "use rusteero::auth::flow::LoginFlow;",
    "use rusteero::transport::Transport;",
    "use rusteero::storage::{clear_async, save_async};",
    "use rusteero::{ChainedStore, CredentialStore, FileStore, KeyringStore};",
    "let flow = LoginFlow::with_transport(transport);",
    "let mut b = Transport::builder();",
    "let b = b.base_url(url);",
    "let store = FileStore::new(path.clone());",
    "let store = ChainedStore::new(Arc::clone(keyring), Arc::new(FileStore::new(path.clone())));",
    "let store = KeyringStore::with_entry(OWN_KEYRING_SERVICE, OWN_KEYRING_ACCOUNT).warn_on_unpersisted(false);",
    "save_async(store, session).await?;",
    "clear_async(store).await?;",
    "client.logout().await",
    "let backend: Arc<dyn CredentialStore> = backend;",
    "fn pending(p: &PendingLogin) {}",
];

#[test]
fn the_login_module_may_name_its_items_and_no_other_file_may() {
    for allowed in AUTH_ONLY_SNIPPETS {
        assert_eq!(
            findings(AUTH_FILE, allowed),
            Vec::<String>::new(),
            "{allowed}"
        );
        for elsewhere in [
            "src/x.rs",
            "src/server.rs",
            "src/cli.rs",
            "src/credentials.rs",
            "src/tools/login.rs",
            "src/main.rs",
        ] {
            // server.rs applies the Client's own base URL, once.
            if elsewhere == "src/server.rs" && allowed.contains("base_url(") {
                continue;
            }
            assert!(
                !findings(elsewhere, allowed).is_empty(),
                "{elsewhere} must not contain: {allowed}"
            );
        }
    }
}

#[test]
fn the_login_modules_constructors_are_the_only_way_in() {
    for sneaky in [
        // The shared keyring entry and rusteero's own service constant.
        "let s = KeyringStore::new();",
        "let s = KeyringStore::with_entry(\"eero-api\", \"auth-tokens\");",
        "let s = KeyringStore::with_entry(SERVICE_NAME, ACCOUNT_NAME);",
        "let s = KeyringStore::with_entry(OWN_KEYRING_SERVICE, \"auth-tokens\");",
        "let s = KeyringStore::with_entry(\"eero-mcp\", OWN_KEYRING_ACCOUNT);",
        "let s = KeyringStore::default();",
        "use rusteero::storage::keyring::SERVICE_NAME;",
        // A login flow on the real hosts.
        "let f = LoginFlow::new(None)?;",
        // Anything but the one constructor, and any load.
        "let s = FileStore::default();",
        "let s = FileStore::from(p);",
        "let s = ChainedStore::default();",
        "let session = store.load()?;",
        "let session = load_async(store).await?;",
        "let s = MemoryStore::new();",
        "use rusteero::MemoryStore;",
        "let s = create_storage(&config);",
        "let c = StorageConfig::default();",
        "let b = TransportBuilder::default();",
        "use rusteero::transport::TransportBuilder;",
        "let t = Transport::request(a, b);",
        // Paths below the Client other than the exact ones.
        "use rusteero::storage::{save_async, load_async};",
        "use rusteero::storage::load_async;",
        "use rusteero::auth::flow::{LoginFlow, SomethingElse};",
        "use rusteero::auth::AuthApi;",
        "use rusteero::client::Client;",
        "use rusteero::storage::keyring::KeyringStore;",
        "use rusteero::endpoints::events::SOMETHING_ELSE;",
        // The shared and explicit credentials, and eeroctl's file, are never handed over.
        "let p = settings.session_file.clone();",
        "let p = settings.default_session_file.clone();",
        "let p = SESSION_FILE_VAR;",
        "let p = EEROCTL_CONFIG_DIR_VAR;",
        "let p = COOKIES_FILE;",
        // Still banned everywhere, the login module included.
        "client.set_dhcp(true).await;",
        "client.set_session_token(t).await;",
        "let s = Session::from_env(\"X\");",
        "std::fs::write(p, d)?;",
        "client.api().devices()",
    ] {
        assert!(
            !findings(AUTH_FILE, sneaky).is_empty(),
            "{AUTH_FILE} must not contain: {sneaky}"
        );
    }
    // Prose naming a load is fine; a call is not.
    assert!(
        findings(
            AUTH_FILE,
            "// the loader never runs; nothing here loads a store"
        )
        .is_empty()
    );
}

#[test]
fn the_login_transports_builder_and_base_url_are_used_once_each_in_the_login_module_only() {
    let once = "let mut b = Transport::builder(); b = b.base_url(url); b.build()";
    assert_eq!(findings(AUTH_FILE, once), Vec::<String>::new());
    assert!(!findings("src/server.rs", once).is_empty());
    assert!(!findings(AUTH_FILE, &format!("{once}; {once}")).is_empty());
    assert!(
        !findings(
            AUTH_FILE,
            "let a = Transport::builder(); let b = Transport::builder();"
        )
        .is_empty()
    );
    assert!(!findings(AUTH_FILE, "b.base_url(one); b.base_url(two);").is_empty());
    // The Client's session accessor, builder and builder factory stay out of the login module.
    for sneaky in [
        "client.session()",
        "Client::builder()",
        "client_builder(url, token).build()",
        "client_builder(url, token).base_url(other)",
    ] {
        assert!(!findings(AUTH_FILE, sneaky).is_empty(), "{sneaky}");
    }
    // Client construction in server.rs is unaffected by the transport pins.
    assert!(findings("src/server.rs", "Client::builder().base_url(u).session(s)").is_empty());
}

#[test]
fn the_login_modules_unit_tests_may_not_name_a_store_or_a_mock_server() {
    let clean = "fn f() {}\n#[cfg(test)]\nmod tests {\n    fn t() { let _ = 1; }\n}\n";
    assert_eq!(findings(AUTH_FILE, clean), Vec::<String>::new());
    for name in AUTH_TEST_MODULE_BANNED {
        let source = format!(
            "fn f() {{}}\n#[cfg(test)]\nmod tests {{\n    fn t() {{ let _ = {name}; }}\n}}\n"
        );
        assert!(
            !findings(AUTH_FILE, &source).is_empty(),
            "{name} in the login module's unit tests"
        );
    }
    // Other files' unit tests are not held to this rule.
    let other =
        "fn f() {}\n#[cfg(test)]\nmod tests {\n    fn t() { let _ = tempfile::tempdir(); }\n}\n";
    assert_eq!(findings("src/credentials.rs", other), Vec::<String>::new());
}

#[test]
fn grouped_paths_expand_member_by_member() {
    assert_eq!(
        expand_group("rusteero::auth::flow::{LoginFlow,PendingLogin}"),
        [
            "rusteero::auth::flow::LoginFlow",
            "rusteero::auth::flow::PendingLogin"
        ]
    );
    assert_eq!(
        expand_group("rusteero::routes::ApiVersion"),
        ["rusteero::routes::ApiVersion"]
    );
    assert!(rusteero_path_allowed(
        AUTH_FILE,
        "rusteero::storage::{clear_async,save_async}"
    ));
    assert!(!rusteero_path_allowed(
        AUTH_FILE,
        "rusteero::storage::{clear_async,load_async}"
    ));
    assert!(!rusteero_path_allowed(
        "src/x.rs",
        "rusteero::storage::{clear_async,save_async}"
    ));
    // The pre-existing grouped exception still passes everywhere.
    assert!(rusteero_path_allowed(
        "src/credentials.rs",
        "rusteero::storage::keyring::{ACCOUNT_NAME,SERVICE_NAME}"
    ));
}

#[test]
fn canonicalising_a_path_is_a_read_and_the_rest_of_the_file_system_stays_banned() {
    assert_eq!(
        findings("src/credentials.rs", "let c = std::fs::canonicalize(p)?;"),
        Vec::<String>::new()
    );
    for sneaky in [
        "std::fs::copy(a, b)?;",
        "std::fs::create_dir_all(p)?;",
        "std::fs::hard_link(a, b)?;",
        "std::fs::symlink_metadata_and_write(p)?;",
    ] {
        assert!(
            !findings("src/credentials.rs", sneaky).is_empty(),
            "{sneaky}"
        );
    }
}

// ===================== constructor bypasses and the login wrappers =====================

#[test]
fn the_shared_keyring_entry_cannot_be_built_by_a_default_an_alias_or_an_inferred_type() {
    for sneaky in [
        // The default store is the shared entry (eero-api / auth-tokens).
        "let shared: KeyringStore = Default::default();",
        "let s = <KeyringStore as Default>::default();",
        "let s = Arc::<KeyringStore>::default();",
        "let s: Arc<KeyringStore> = Arc::default();",
        "let s = KeyringStore::default();",
        // A rename hides the type from the name-based rules.
        "use rusteero::KeyringStore as K; let s = K::new();",
        "use rusteero::{KeyringStore as K};",
        "use rusteero::{ChainedStore, KeyringStore as Keys, FileStore};",
        "use rusteero as r;",
        "use rusteero::{self as r};",
        // A type alias or an annotation names the type without constructing it through with_entry.
        "type K = KeyringStore;",
        "fn shared() -> KeyringStore { todo!() }",
        "let s = rusteero::KeyringStore::new();",
        // with_entry with anything but the two own constants, in that order and nothing else.
        "let s = KeyringStore::with_entry(OWN_KEYRING_ACCOUNT, OWN_KEYRING_SERVICE);",
        "let s = KeyringStore::with_entry(OWN_KEYRING_SERVICE, OWN_KEYRING_ACCOUNT, extra);",
        "let s = KeyringStore::with_entry(OWN_KEYRING_SERVICE /* OWN_KEYRING_ACCOUNT */, \"auth-tokens\");",
        "let s = KeyringStore::with_entry(&service, &account);",
        // The same discipline for the other stores, the flow and the transport.
        "let s: FileStore = Default::default();",
        "type F = FileStore;",
        "let s = FileStore::new(other_path);",
        "let s = FileStore::new(settings.own_file.clone());",
        "let c: ChainedStore = make();",
        "let c = ChainedStore::new(a, b);",
    ] {
        assert!(
            !findings(AUTH_FILE, sneaky).is_empty(),
            "{AUTH_FILE} must not contain: {sneaky}"
        );
    }
    // Any use of the pattern elsewhere is banned by the type names themselves.
    for sneaky in [
        "let shared: KeyringStore = Default::default();",
        "use rusteero::KeyringStore as K;",
    ] {
        for elsewhere in ["src/cli.rs", "src/server.rs", "src/tools/login.rs"] {
            assert!(!findings(elsewhere, sneaky).is_empty(), "{sneaky}");
        }
    }
    // The shapes the login module really uses stay fine.
    for fine in [
        "use rusteero::{ChainedStore, CredentialStore, Error, FileStore, Session, StorageError};",
        "#[cfg(feature = \"keyring\")]\nuse rusteero::KeyringStore;",
        "let k = Arc::new(KeyringStore::with_entry(OWN_KEYRING_SERVICE, OWN_KEYRING_ACCOUNT).warn_on_unpersisted(false));",
        "let k = KeyringStore::with_entry(\n    OWN_KEYRING_SERVICE,\n    OWN_KEYRING_ACCOUNT,\n);",
        "let f = Arc::new(FileStore::new(path.clone()));",
        "let c = ChainedStore::new(Arc::clone(keyring), Arc::new(FileStore::new(path.clone())));",
        "let v = x.unwrap_or_default(); // the default is empty",
    ] {
        assert_eq!(findings(AUTH_FILE, fine), Vec::<String>::new(), "{fine}");
    }
}

#[test]
fn default_is_banned_in_the_login_module_and_prose_is_not() {
    assert!(!findings(AUTH_FILE, "#[derive(Default)]\nstruct Report;").is_empty());
    assert!(!findings(AUTH_FILE, "let r = Report::default();").is_empty());
    assert!(!findings(AUTH_FILE, "let r: Report = Default::default();").is_empty());
    assert!(!findings(AUTH_FILE, "let r = std::default::Default::default();").is_empty());
    assert_eq!(
        findings(
            AUTH_FILE,
            "// the default is none\nlet r = x.unwrap_or_default();"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn a_use_statement_cannot_hide_the_code_after_it() {
    // A line that merely starts with the word use inside a comment or a string is not a statement.
    for sneaky in [
        "// use the shared one\nlet s: KeyringStore = make();",
        "/// use it\nlet s: KeyringStore = make();",
        "let note = \"x \\\n use y\";\nlet s: KeyringStore = make();",
        "use rusteero::KeyringStore; let s: KeyringStore = make();",
    ] {
        assert!(!findings(AUTH_FILE, sneaky).is_empty(), "{sneaky}");
    }
}

#[test]
fn renaming_an_import_from_rusteero_is_banned_in_every_file() {
    for elsewhere in [
        AUTH_FILE,
        "src/server.rs",
        "src/ids.rs",
        "src/cli.rs",
        "src/tools/login.rs",
        "src/tools/devices.rs",
    ] {
        for sneaky in [
            "use rusteero::Client as C;",
            "use rusteero::{Client as C, Error};",
            "pub use rusteero::Error as E;",
            "use rusteero as r;",
        ] {
            assert!(
                !findings(elsewhere, sneaky).is_empty(),
                "{elsewhere}: {sneaky}"
            );
        }
        // Other crates' renames and plain imports are fine.
        for fine in [
            "use rmcp::ServiceExt as _;",
            "use anyhow::Context as _;",
            "use rusteero::{Client, Error};",
        ] {
            assert_eq!(findings(elsewhere, fine), Vec::<String>::new(), "{fine}");
        }
    }
}

#[test]
fn the_login_wrappers_are_callable_from_the_files_that_need_them_only() {
    // (call, files that may contain it)
    let pins: &[(&str, &[&str])] = &[
        (
            "let t = run_login(None, Some(id), &mut p, None, &budget).await;",
            &[AUTH_FILE, "src/cli.rs", "src/tools/login.rs"],
        ),
        (
            "let k = save_session(&store, &chain, &token).await;",
            &[AUTH_FILE, "src/cli.rs", "src/tools/login.rs"],
        ),
        (
            "let r = revoke_replaced(url, &chain, saved).await;",
            &[AUTH_FILE, "src/cli.rs", "src/tools/login.rs"],
        ),
        (
            "let _ = revoke_session(url, &token).await;",
            &[AUTH_FILE, "src/cli.rs"],
        ),
        (
            "let r = sign_out_own_session(url, &store, &chain).await;",
            &[AUTH_FILE, "src/cli.rs"],
        ),
        ("store.clear_all().await;", &[AUTH_FILE]),
        (
            "let store = OwnStore::production(&settings);",
            &[AUTH_FILE, "src/cli.rs", "src/main.rs"],
        ),
    ];
    let every_file = [
        AUTH_FILE,
        "src/cli.rs",
        "src/main.rs",
        "src/tools/login.rs",
        "src/tools/account.rs",
        "src/tools/devices.rs",
        "src/server.rs",
        "src/credentials.rs",
        "src/config.rs",
        "src/ids.rs",
        "src/lib.rs",
    ];
    for (call, allowed) in pins {
        for file in every_file {
            let found = findings(file, call);
            if allowed.contains(&file) {
                assert_eq!(found, Vec::<String>::new(), "{file} may contain: {call}");
            } else {
                assert!(!found.is_empty(), "{file} must not contain: {call}");
            }
        }
    }
    // Each is caught however it is reached: a path, a use line, an alias, a re-export.
    for sneaky in [
        "crate::auth::run_login(None, None, &mut p, None, &b).await",
        "use crate::auth::{OwnStore, save_session};",
        "use crate::auth::revoke_session as rs;",
        "pub use crate::auth::sign_out_own_session;",
        "let f = crate::auth::save_session;",
        "// calls run_login",
        "let store = <OwnStore>::production(&settings);",
        "let store = OwnStore::new(None, settings.session_file.clone());",
        "let store = OwnStore::new(None, settings.default_session_file.clone());",
        "let store = OwnStore::with_backends(None, Some(path));",
        "let store = OwnStore::from_parts(None, Some(path));",
    ] {
        assert!(
            !findings("src/tools/account.rs", sneaky).is_empty(),
            "{sneaky}"
        );
    }
    // The type itself may be named anywhere (the login tool holds one).
    assert_eq!(
        findings(
            "src/tools/login.rs",
            "use crate::auth::OwnStore;\nstruct S { store: OwnStore }"
        ),
        Vec::<String>::new()
    );
}

#[test]
fn the_injectable_store_constructor_is_defined_once_and_never_called_in_src() {
    // Only the definition in the login module, once.
    assert_eq!(
        findings(
            AUTH_FILE,
            "pub fn with_backends(keyring: Option<K>, file: Option<P>) -> Self { Self { keyring, file } }"
        ),
        Vec::<String>::new()
    );
    for sneaky in [
        "let s = Self::with_backends(None, Some(p));",
        "let s = OwnStore::with_backends(None, Some(p));",
        "let s = OwnStore::with_backends(None, settings.own_file.clone());",
        "pub fn with_backends() {}\npub fn with_backends() {}",
        "// OwnStore::with_backends",
        "let f = OwnStore::with_backends;",
    ] {
        assert!(!findings(AUTH_FILE, sneaky).is_empty(), "{sneaky}");
    }
    for elsewhere in [
        "src/cli.rs",
        "src/main.rs",
        "src/tools/login.rs",
        "src/server.rs",
    ] {
        for sneaky in [
            "pub fn with_backends() {}",
            "let s = OwnStore::with_backends(None, Some(p));",
        ] {
            assert!(
                !findings(elsewhere, sneaky).is_empty(),
                "{elsewhere}: {sneaky}"
            );
        }
    }
}

#[test]
fn the_own_file_path_reaches_the_store_from_the_settings_own_file_only() {
    // Read once, in the production constructor.
    assert_eq!(
        findings(
            AUTH_FILE,
            "pub fn production(settings: &Settings) -> Self { Self { keyring, file: settings.own_file.clone() } }"
        ),
        Vec::<String>::new()
    );
    // Other files cannot rewrite it (to the explicit file's path, say) before the store is built.
    for elsewhere in [
        "src/cli.rs",
        "src/main.rs",
        "src/tools/login.rs",
        "src/server.rs",
    ] {
        for sneaky in [
            "settings.own_file = settings.session_file.clone();",
            "let s = Settings { own_file: x, ..settings.clone() };",
            "let p = settings.own_file.clone();",
        ] {
            assert!(
                !findings(elsewhere, sneaky).is_empty(),
                "{elsewhere}: {sneaky}"
            );
        }
        // The explicit-file check is a different name and stays fine everywhere.
        assert_eq!(
            findings(elsewhere, "let own = chain.explicit_file_is_own_file();"),
            Vec::<String>::new()
        );
    }
    for definer in ["src/config.rs", "src/credentials.rs"] {
        assert_eq!(
            findings(definer, "pub own_file: Option<PathBuf>,"),
            Vec::<String>::new(),
            "{definer}"
        );
    }
    for sneaky in [
        "let p = settings.own_file.clone(); let q = settings.own_file.clone();",
        "let p = settings.own_file.as_deref();",
        "let p = other.own_file.clone();",
        "let p = own_file;",
        "let p = settings.session_file.clone();",
        "let p = settings.default_session_file.clone();",
    ] {
        assert!(!findings(AUTH_FILE, sneaky).is_empty(), "{sneaky}");
    }
}
