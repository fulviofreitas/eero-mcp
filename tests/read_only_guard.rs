//! The read-only guard: scans every file under `src/` and fails if the source could issue a write.
//!
//! The server's source must be *unable* to issue a write, not merely told not to. Identifier-boundary
//! matches count wherever they appear, comments included: `src/` never names them. What is banned:
//!
//! - every rusteero `Client` / `ClientBuilder` method that is not one of the 40 catalogue reads
//!   (writes and actions, session and credential-store setters, and the 38 reads that no tool
//!   exposes), generated from rusteero v3.0.0 and cross-checked against the dependency's real
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
//! The banned lists are generated from rusteero v3.0.0's `Client` (`src/client/*.rs`): every public
//! function that is not one of its 78 reads, minus the read-only accessors and harmless builder
//! setters; plus the 38 reads that are not part of the 40-tool catalogue. After a rusteero bump the
//! drift test names every function that needs classifying; the lists are regenerated with:
//!
//! ```text
//! for f in $(git -C <rusteero> ls-tree --name-only v3.0.0 src/client/); do
//!   git -C <rusteero> show "v3.0.0:$f" | grep -oE 'pub (async )?fn [a-z0-9_]+'
//! done | awk '{print $NF}' | sort -u
//! ```

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Every non-read `Client` and `ClientBuilder` method of rusteero v3.0.0 (the pinned
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

/// The 38 reads of rusteero v3.0.0 that are not among the 40 catalogue tools: never called.
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

/// The only file-system items non-test code may use: reading one regular file.
const ALLOWED_FS_PATHS: &[&str] = &[
    "fs::read_to_string",
    "fs::metadata",
    "fs::File::open",
    "fs::File",
];

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
    report.findings
}

/// Rusteero methods, credential-store types and the lower-layer functions.
fn scan_banned_names(report: &mut Report<'_>) {
    let text = report.text;
    for name in WRITE_AND_ACTION_METHODS.iter().chain(UNEXPOSED_READS) {
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
        for offset in ident_matches(text, name) {
            report.at(
                offset,
                format!("`{name}` writes, refreshes a session or bypasses the Client"),
            );
        }
    }
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
            && !ALLOWED_RUSTEERO_PATHS
                .iter()
                .any(|allowed| path_allowed(&path_text, allowed))
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
        if report.path != CLIENT_BUILD_FILE {
            for offset in uses {
                report.at(
                    offset,
                    format!(
                        "`{name}` decides where the session token goes; it is allowed in \
                         {CLIENT_BUILD_FILE} only"
                    ),
                );
            }
        } else if *name == ORIGIN_SETTER && uses.len() > 1 {
            report.at(
                uses[1],
                format!("`{name}` may be applied exactly once in {CLIENT_BUILD_FILE}"),
            );
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
        "rusteero v3.0.0 has 78 reads"
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
