//! Id validation and canonicalisation, and default-network resolution.
//!
//! Every id a tool accepts is validated here, before any request, with rusteero's own public
//! validators against the **configured** API origin, then reduced to its bare last segment so
//! rusteero's cache keys stay consistent (rusteero keys network ids verbatim, so `123` and
//! `/2.2/networks/123` would otherwise be two cache entries).
//!
//! | Field | Accepted forms | Family check |
//! |---|---|---|
//! | `network_id` | bare id; `/2.2/networks/ID`; absolute URL on the API origin | networks |
//! | `eero_id` | bare id; `/2.2/eeros/ID`; absolute URL on the API origin | eeros |
//! | `device_id` | bare id (a MAC passes the identifier rule); path or URL under the same network's devices | must belong to the addressed network |
//! | `profile_id` | bare id; path or URL under the same network's profiles | must belong to the addressed network |
//! | `device_mac` | the MAC as `list_devices` shows it | identifier rule only |
//!
//! Validation order: a JSON integer was already rendered in decimal by [`IdInput`]; surrounding
//! whitespace is trimmed; an empty result is `invalid_argument` and is never passed on (rusteero
//! treats an empty network id as absent and would auto-discover); a bare id must satisfy rusteero's
//! single-segment identifier rule; a path or URL must pass rusteero's plain-path, family and origin
//! rules. Messages are rusteero's fixed catalogue text and never echo the input.
//!
//! [`Ids`] is the only place in the crate that touches the Client's raw API accessor, and only to
//! read the configured API host (rusteero exposes it no other way). The read-only guard test pins
//! that one chain, in this file.

use rusteero::Client;
use rusteero::links::validate_identifier;
use rusteero::params::resolve_nested_url;
use rusteero::routes::ApiVersion;
use rusteero::util::id_from_url;
use serde_json::Value;
use url::Url;

use crate::errors::{ToolError, map_error};
use crate::params::IdInput;

/// The longest network name quoted in an ambiguity message.
const NAME_LIMIT: usize = 80;

/// The result of validating an optional `network_id` before any upstream call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkChoice {
    /// A validated, canonical bare network id.
    Explicit(String),
    /// No `network_id` was given: resolve the account's only network.
    Default,
}

/// The two child families nested under a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildKind {
    /// `networks/ID/devices/ID`.
    Device,
    /// `networks/ID/profiles/ID`.
    Profile,
}

impl ChildKind {
    /// The tool parameter name.
    pub const fn field(self) -> &'static str {
        match self {
            Self::Device => "device_id",
            Self::Profile => "profile_id",
        }
    }

    /// The collection segment under the network.
    const fn prefix(self) -> &'static str {
        match self {
            Self::Device => "devices",
            Self::Profile => "profiles",
        }
    }
}

/// A child id that passed the network-independent checks.
///
/// A bare id is complete. A path or URL must still be checked against the addressed network with
/// [`Ids::in_network`] once that network is known (immediately when `network_id` was supplied,
/// otherwise right after default-network resolution), still before the read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildId {
    kind: ChildKind,
    canonical: String,
    /// The trimmed path or URL, when the network membership check is still outstanding.
    pending: Option<String>,
}

impl ChildId {
    /// The canonical bare id.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// The tool parameter this id came from (`device_id` or `profile_id`).
    pub fn param(&self) -> &'static str {
        self.kind.field()
    }

    /// Whether [`Ids::in_network`] has real work to do (the id was a path or URL).
    pub fn needs_network_check(&self) -> bool {
        self.pending.is_some()
    }
}

/// Validates ids against the configured API origin.
#[derive(Debug, Clone, Copy)]
pub struct Ids<'a> {
    host: &'a Url,
}

/// Whether `value` starts with `prefix`, ignoring ASCII case.
fn starts_with_ignore_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Whether `value` is a path or an absolute http(s) URL rather than a bare id. The scheme is
/// matched case-insensitively, as rusteero's resource URL builder does.
fn is_path_or_url(value: &str) -> bool {
    value.starts_with('/')
        || starts_with_ignore_case(value, "http://")
        || starts_with_ignore_case(value, "https://")
}

/// Lowercases an http(s) scheme. rusteero's nested-URL resolver only recognises a lowercase
/// `http://` or `https://`; with `HTTP://` it would take the whole URL for a bare id and report an
/// unrelated error. `network_id` and `eero_id` accept any case (rusteero's resource URL builder is
/// case-insensitive), so the child ids must too.
fn lowercase_scheme(value: &str) -> String {
    for scheme in ["https://", "http://"] {
        if starts_with_ignore_case(value, scheme) {
            return format!("{scheme}{}", &value[scheme.len()..]);
        }
    }
    value.to_owned()
}

/// Trims, and rejects an empty result.
fn trimmed<'v>(field: &'static str, raw: &'v str) -> Result<&'v str, ToolError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ToolError::invalid_argument(field, "must be a non-empty id"));
    }
    Ok(value)
}

/// Validates a bare identifier for `field`.
fn bare(field: &'static str, value: &str) -> Result<String, ToolError> {
    validate_identifier(value)
        .map(str::to_owned)
        .map_err(|error| map_error(&error, Some(field)))
}

/// The canonical bare id of a validated path or URL: its last segment, which must itself satisfy
/// the identifier rule (defence in depth: the family check does not apply it to the id segment).
fn last_segment(field: &'static str, value: &str) -> Result<String, ToolError> {
    let segment = id_from_url(value).map_err(|error| map_error(&error, Some(field)))?;
    bare(field, &segment)
}

impl<'a> Ids<'a> {
    /// Validators bound to an explicit API host (unit tests use `http://mock.test:1234`).
    pub fn from_host(host: &'a Url) -> Self {
        Self { host }
    }

    /// Validators bound to the Client's configured API host.
    ///
    /// This is the single allowed use of the Client's raw API accessor in the crate.
    pub fn for_client(client: &'a Client) -> Self {
        Self::from_host(client.api().transport().api_host())
    }

    /// Validates a top-level resource id (`networks` or `eeros` family).
    fn top_level(
        self,
        field: &'static str,
        raw: &str,
        template: &str,
    ) -> Result<String, ToolError> {
        let value = trimmed(field, raw)?;
        rusteero::resource_url(self.host, value, template, ApiVersion::V2_2)
            .map_err(|error| map_error(&error, Some(field)))?;
        if is_path_or_url(value) {
            last_segment(field, value)
        } else {
            bare(field, value)
        }
    }

    /// Validates an optional `network_id`: a supplied id is canonicalised to its bare form, an
    /// omitted one (or JSON null) means default-network resolution.
    pub fn network(self, raw: Option<&IdInput>) -> Result<NetworkChoice, ToolError> {
        match raw {
            None => Ok(NetworkChoice::Default),
            Some(id) => self
                .top_level("network_id", id.as_str(), "networks/{id}")
                .map(NetworkChoice::Explicit),
        }
    }

    /// Validates an `eero_id` (required by `get_eero` and `list_eero_connections`, an optional
    /// filter of `get_channel_utilization`): bare id, `/2.2/eeros/ID`, or an absolute URL on the
    /// API origin.
    pub fn eero(self, raw: &IdInput) -> Result<String, ToolError> {
        self.top_level("eero_id", raw.as_str(), "eeros/{id}")
    }

    /// Validates a `device_id`. A path or URL needs [`Ids::in_network`] afterwards.
    pub fn device(self, raw: &IdInput) -> Result<ChildId, ToolError> {
        self.child(ChildKind::Device, raw.as_str())
    }

    /// Validates a `profile_id`. A path or URL needs [`Ids::in_network`] afterwards.
    pub fn profile(self, raw: &IdInput) -> Result<ChildId, ToolError> {
        self.child(ChildKind::Profile, raw.as_str())
    }

    fn child(self, kind: ChildKind, raw: &str) -> Result<ChildId, ToolError> {
        let field = kind.field();
        let value = trimmed(field, raw)?;
        if !is_path_or_url(value) {
            return Ok(ChildId {
                kind,
                canonical: bare(field, value)?,
                pending: None,
            });
        }
        // rusteero's nested-family check strips every trailing slash; the accepted forms allow at
        // most one, exactly as for `network_id` and `eero_id`.
        if value.ends_with("//") {
            return Err(ToolError::invalid_argument(
                field,
                "must not end with more than one slash",
            ));
        }
        let value = lowercase_scheme(value);
        // An empty network id skips only the membership comparison; every shape, family and
        // origin rule still applies.
        resolve_nested_url(
            self.host,
            "",
            &value,
            kind.prefix(),
            "",
            None,
            None,
            ApiVersion::V2_2,
        )
        .map_err(|error| map_error(&error, Some(field)))?;
        Ok(ChildId {
            kind,
            canonical: last_segment(field, &value)?,
            pending: Some(value),
        })
    }

    /// Completes a child id's check against the addressed network and returns its canonical bare
    /// id. A path or URL that names another network is `invalid_argument`.
    pub fn in_network(self, child: &ChildId, network_id: &str) -> Result<String, ToolError> {
        if let Some(raw) = &child.pending {
            resolve_nested_url(
                self.host,
                network_id,
                raw,
                child.kind.prefix(),
                "",
                None,
                None,
                ApiVersion::V2_2,
            )
            .map_err(|error| map_error(&error, Some(child.kind.field())))?;
        }
        Ok(child.canonical.clone())
    }
}

/// Validates the `device_mac` of `get_device_data_usage`: the MAC as `list_devices` shows it,
/// under rusteero's single-segment identifier rule.
pub fn device_mac(raw: &IdInput) -> Result<String, ToolError> {
    let value = trimmed("device_mac", raw.as_str())?;
    bare("device_mac", value)
}

/// A network entry's id: a non-empty string `id`, or a non-zero unsigned integer `id`, else the
/// last segment of `url`; in every case it must satisfy the identifier rule.
pub fn network_entry_id(entry: &Value) -> Option<String> {
    let from_id = match entry.get("id") {
        Some(Value::String(id)) if !id.is_empty() => Some(id.clone()),
        Some(Value::Number(number)) => number
            .as_u64()
            .filter(|id| *id != 0)
            .map(|id| id.to_string()),
        _ => None,
    };
    if let Some(id) = from_id.filter(|id| validate_identifier(id).is_ok()) {
        return Some(id);
    }
    let url = entry
        .get("url")
        .and_then(Value::as_str)
        .filter(|url| !url.is_empty())?;
    let segment = id_from_url(url).ok()?;
    validate_identifier(&segment).ok()?;
    Some(segment)
}

/// A printable, bounded rendition of a network name for an ambiguity message.
fn display_name(entry: &Value) -> String {
    let name = entry
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(NAME_LIMIT)
        .collect();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        "unnamed".to_owned()
    } else {
        cleaned.to_owned()
    }
}

/// Picks the default network from the unwrapped network list.
///
/// - exactly one network: its id;
/// - none: `not_found`, "no networks on this account";
/// - several: `invalid_argument` with field `network_id`, listing each network's id and name so
///   the agent can choose. The first network is never picked silently.
pub fn pick_default_network(networks: &[Value]) -> Result<String, ToolError> {
    match networks {
        [] => Err(ToolError::not_found("no networks on this account")),
        [only] => network_entry_id(only).ok_or_else(ToolError::unexpected_response),
        several => {
            let listing: Vec<String> = several
                .iter()
                .map(|entry| {
                    let id = network_entry_id(entry).unwrap_or_else(|| "(no usable id)".to_owned());
                    format!("{id} ({})", display_name(entry))
                })
                .collect();
            Err(ToolError::invalid_argument(
                "network_id",
                format!(
                    "this account has {} networks; pass network_id as one of: {}",
                    several.len(),
                    listing.join(", ")
                ),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::errors::ErrorCode;

    /// The configured origin in these tests is never the production host.
    fn host() -> Url {
        Url::parse("http://mock.test:1234").expect("url")
    }

    fn id(value: &str) -> IdInput {
        IdInput::new(value)
    }

    fn network(raw: &str) -> Result<NetworkChoice, ToolError> {
        Ids::from_host(&host()).network(Some(&id(raw)))
    }

    fn explicit(raw: &str) -> String {
        match network(raw).expect("valid") {
            NetworkChoice::Explicit(id) => id,
            NetworkChoice::Default => panic!("expected an explicit id"),
        }
    }

    // ===================== network_id =====================

    #[test]
    fn an_omitted_network_id_means_default_resolution() {
        assert_eq!(
            Ids::from_host(&host()).network(None).expect("ok"),
            NetworkChoice::Default
        );
    }

    #[test]
    fn network_id_forms_all_canonicalise_to_the_bare_id() {
        for raw in [
            "network-0001",
            "  network-0001  ",
            "/2.2/networks/network-0001",
            "/2.2/networks/network-0001/",
            "/2.3/networks/network-0001",
            "/10.12/networks/network-0001",
            "http://mock.test:1234/2.2/networks/network-0001",
            "http://mock.test:1234/2.2/networks/network-0001/",
            "HTTP://MOCK.TEST:1234/2.2/networks/network-0001",
        ] {
            assert_eq!(explicit(raw), "network-0001", "{raw:?}");
        }
    }

    #[test]
    fn a_numeric_id_rendered_by_the_integer_path_is_valid() {
        let numeric: IdInput = serde_json::from_value(json!(12345)).expect("integer id");
        assert_eq!(
            Ids::from_host(&host())
                .network(Some(&numeric))
                .expect("valid"),
            NetworkChoice::Explicit("12345".to_owned())
        );
    }

    #[test]
    fn empty_and_whitespace_ids_are_rejected_and_never_passed_on() {
        for raw in ["", " ", "\t\n", "   "] {
            let error = network(raw).expect_err("empty");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
            assert_eq!(error.field.as_deref(), Some("network_id"), "{raw:?}");
        }
    }

    #[test]
    fn malformed_network_ids_are_rejected_with_the_parameter_name() {
        for raw in [
            "../hostile-0001",
            "a/b",
            "a..b",
            "-leading",
            "_leading",
            "has space",
            "has\tnewline\n",
            "query?x=1",
            "frag#x",
            "percent%2e",
            "back\\slash",
            "caf\u{e9}",
            "networks/network-0001",
            "/2.2/networks/",
            "/2.2/networks",
            "/2.2/account",
            "/2.2/eeros/eero-0001",
            "/2.2/networks/network-0001/devices",
            "/2.2/networks/network-0001/devices/device-0001",
            "/2.2/networks/../networks/network-0001",
            "/2.2/networks/%2e%2e",
            "/2.2/networks/network-0001?x=1",
            "/2.2/networks/network-0001#x",
            "/2.2/networks/network-0001//",
            "/networks/network-0001",
            "//mock.test:1234/2.2/networks/network-0001",
            "/2.2/networks/net work",
        ] {
            let error = network(raw).expect_err(raw);
            assert_eq!(error.code, ErrorCode::InvalidArgument, "{raw:?}");
            assert_eq!(error.field.as_deref(), Some("network_id"), "{raw:?}");
        }
    }

    #[test]
    fn foreign_origins_are_rejected() {
        for raw in [
            "https://api-user.e2ro.com/2.2/networks/network-0001",
            "http://api-user.e2ro.com/2.2/networks/network-0001",
            "http://mock.test:9999/2.2/networks/network-0001",
            "https://mock.test:1234/2.2/networks/network-0001",
            "http://other.test:1234/2.2/networks/network-0001",
            "http://user@mock.test:1234/2.2/networks/network-0001",
            "http://mock.test:1234@evil.test/2.2/networks/network-0001",
            "http://mock.test.evil.test:1234/2.2/networks/network-0001",
            "ftp://mock.test:1234/2.2/networks/network-0001",
        ] {
            let error = network(raw).expect_err(raw);
            assert_eq!(error.code, ErrorCode::InvalidArgument, "{raw:?}");
            assert_eq!(error.field.as_deref(), Some("network_id"), "{raw:?}");
        }
    }

    #[test]
    fn the_production_host_is_rejected_when_the_configured_origin_is_a_mock() {
        // The fixture host must differ from production, or this would hide a branch that reads
        // the production constant instead of the configured host.
        assert!(network("https://api-user.e2ro.com/2.2/networks/1").is_err());
        let production = Url::parse("https://api-user.e2ro.com").expect("url");
        let ids = Ids::from_host(&production);
        assert!(
            ids.network(Some(&id("https://api-user.e2ro.com/2.2/networks/1")))
                .is_ok()
        );
        assert!(
            ids.network(Some(&id("http://mock.test:1234/2.2/networks/1")))
                .is_err()
        );
    }

    #[test]
    fn validation_messages_never_echo_the_input() {
        for raw in [
            "../hostile-0001",
            "https://evil.example/2.2/networks/secret-0001",
            "/2.2/eeros/secret-0002",
            "has secret-0003 space",
        ] {
            let error = network(raw).expect_err(raw);
            let rendered = error.to_value().to_string();
            for leaked in ["hostile", "evil", "secret-000"] {
                assert!(!rendered.contains(leaked), "{rendered}");
            }
        }
    }

    // ===================== eero_id =====================

    #[test]
    fn eero_id_forms_canonicalise_to_the_bare_id() {
        let host = host();
        let ids = Ids::from_host(&host);
        for raw in [
            "eero-0001",
            " eero-0001 ",
            "/2.2/eeros/eero-0001",
            "/2.2/eeros/eero-0001/",
            "http://mock.test:1234/2.2/eeros/eero-0001",
        ] {
            assert_eq!(ids.eero(&id(raw)).expect("valid"), "eero-0001", "{raw:?}");
        }
    }

    #[test]
    fn eero_id_rejects_other_families_foreign_origins_and_garbage() {
        let host = host();
        let ids = Ids::from_host(&host);
        for raw in [
            "",
            "  ",
            "../x",
            "/2.2/networks/network-0001",
            "/2.2/eeros/eero-0001/reboot",
            "https://api-user.e2ro.com/2.2/eeros/eero-0001",
            "eero 0001",
        ] {
            let error = ids.eero(&id(raw)).expect_err(raw);
            assert_eq!(error.code, ErrorCode::InvalidArgument, "{raw:?}");
            assert_eq!(error.field.as_deref(), Some("eero_id"), "{raw:?}");
        }
    }

    // ===================== device_id and profile_id =====================

    #[test]
    fn bare_child_ids_are_complete_and_network_independent() {
        let host = host();
        let ids = Ids::from_host(&host);
        for raw in [
            "device-0001",
            "aa:bb:cc:00:00:01",
            "AA:BB:CC:00:00:01",
            "AA-BB-CC-00-00-01",
            "aabb.ccdd.eeff",
            "aabbcc000001",
        ] {
            let child = ids.device(&id(raw)).expect(raw);
            assert!(!child.needs_network_check(), "{raw}");
            assert_eq!(child.canonical(), raw);
            assert_eq!(ids.in_network(&child, "network-0001").expect("ok"), raw);
            assert_eq!(ids.in_network(&child, "network-0002").expect("ok"), raw);
        }
        let profile = ids.profile(&id("  profile-0001  ")).expect("profile");
        assert_eq!(profile.canonical(), "profile-0001");
    }

    #[test]
    fn child_paths_and_urls_need_the_network_and_must_belong_to_it() {
        let host = host();
        let ids = Ids::from_host(&host);
        for raw in [
            "/2.2/networks/network-0001/devices/device-0001",
            "/2.2/networks/network-0001/devices/device-0001/",
            "http://mock.test:1234/2.2/networks/network-0001/devices/device-0001",
        ] {
            let child = ids.device(&id(raw)).expect(raw);
            assert!(child.needs_network_check(), "{raw}");
            assert_eq!(child.canonical(), "device-0001");
            assert_eq!(
                ids.in_network(&child, "network-0001")
                    .expect("same network"),
                "device-0001"
            );
            let error = ids
                .in_network(&child, "network-0002")
                .expect_err("other network");
            assert_eq!(error.code, ErrorCode::InvalidArgument);
            assert_eq!(error.field.as_deref(), Some("device_id"));
        }
        let profile = ids
            .profile(&id("/2.2/networks/network-0001/profiles/profile-0001"))
            .expect("profile path");
        assert_eq!(
            ids.in_network(&profile, "network-0001").expect("ok"),
            "profile-0001"
        );
        let error = ids
            .in_network(&profile, "network-0009")
            .expect_err("other network");
        assert_eq!(error.field.as_deref(), Some("profile_id"));
    }

    #[test]
    fn child_urls_accept_any_scheme_case_like_network_and_eero_ids() {
        let host = host();
        let ids = Ids::from_host(&host);
        for raw in [
            "HTTP://mock.test:1234/2.2/networks/network-0001/devices/device-0001",
            "Http://MOCK.TEST:1234/2.2/networks/network-0001/devices/device-0001/",
        ] {
            let child = ids.device(&id(raw)).expect(raw);
            assert!(child.needs_network_check(), "{raw}");
            assert_eq!(child.canonical(), "device-0001", "{raw}");
            assert_eq!(
                ids.in_network(&child, "network-0001")
                    .expect("same network"),
                "device-0001"
            );
            assert_eq!(
                ids.in_network(&child, "network-0002")
                    .expect_err("other network")
                    .field
                    .as_deref(),
                Some("device_id")
            );
        }
        let profile = ids
            .profile(&id(
                "HTTPS://mock.test:1234/2.2/networks/network-0001/profiles/profile-0001",
            ))
            .expect_err("https is not the configured origin");
        assert_eq!(profile.field.as_deref(), Some("profile_id"));
        let profile = ids
            .profile(&id(
                "HTTP://mock.test:1234/2.2/networks/network-0001/profiles/profile-0001",
            ))
            .expect("profile url");
        assert_eq!(profile.canonical(), "profile-0001");
        // A foreign origin is rejected whatever the scheme case, with the right parameter and the
        // family message rather than a misleading "non-empty" one.
        for raw in [
            "HTTP://api-user.e2ro.com/2.2/networks/network-0001/devices/device-0001",
            "HTTP://mock.test:9999/2.2/networks/network-0001/devices/device-0001",
        ] {
            let error = ids.device(&id(raw)).expect_err(raw);
            assert_eq!(error.field.as_deref(), Some("device_id"), "{raw}");
            assert!(!error.message.contains("non-empty"), "{}", error.message);
        }
    }

    #[test]
    fn a_child_id_names_its_parameter() {
        let host = host();
        let ids = Ids::from_host(&host);
        assert_eq!(
            ids.device(&id("device-0001")).expect("ok").param(),
            "device_id"
        );
        assert_eq!(
            ids.profile(&id("profile-0001")).expect("ok").param(),
            "profile_id"
        );
    }

    #[test]
    fn the_network_may_itself_have_been_given_as_a_path_form_upstream_of_canonicalisation() {
        // Callers pass the canonical bare network id; the comparison is on bare ids.
        let host = host();
        let ids = Ids::from_host(&host);
        let child = ids
            .device(&id("/2.2/networks/network-0001/devices/device-0001"))
            .expect("path");
        assert!(ids.in_network(&child, "/2.2/networks/network-0001").is_ok());
    }

    #[test]
    fn child_ids_reject_other_families_foreign_origins_and_garbage() {
        let host = host();
        let ids = Ids::from_host(&host);
        for raw in [
            "",
            "   ",
            "../device-0001",
            "device/0001",
            "dev ice",
            "/2.2/networks/network-0001/profiles/profile-0001",
            "/2.2/networks/network-0001/devices",
            "/2.2/networks/network-0001/devices/device-0001/extra",
            // At most one trailing slash, as for network_id and eero_id.
            "/2.2/networks/network-0001/devices/device-0001//",
            "/2.2/networks/network-0001/devices/device-0001///",
            "http://mock.test:1234/2.2/networks/network-0001/devices/device-0001//",
            "HTTP://mock.test:1234/2.2/networks/network-0001/devices/device-0001//",
            "//",
            "/2.2/devices/device-0001",
            "/2.2/networks/network-0001/devices/../devices/device-0001",
            "https://api-user.e2ro.com/2.2/networks/network-0001/devices/device-0001",
            "http://mock.test:9999/2.2/networks/network-0001/devices/device-0001",
            "/2.2/networks/network-0001/devices/dev%2e",
        ] {
            let error = ids.device(&id(raw)).expect_err(raw);
            assert_eq!(error.code, ErrorCode::InvalidArgument, "{raw:?}");
            assert_eq!(error.field.as_deref(), Some("device_id"), "{raw:?}");
        }
        for raw in [
            "/2.2/networks/network-0001/devices/device-0001",
            "/2.2/eeros/eero-0001",
        ] {
            let error = ids.profile(&id(raw)).expect_err(raw);
            assert_eq!(error.field.as_deref(), Some("profile_id"), "{raw:?}");
        }
    }

    #[test]
    fn the_empty_network_check_is_only_the_membership_step() {
        // A path child that is otherwise malformed is rejected at the first phase, even though no
        // network is known yet.
        let host = host();
        let ids = Ids::from_host(&host);
        assert!(
            ids.profile(&id("/2.2/networks/network-0001/profiles/profile-0001?x=1"))
                .is_err()
        );
    }

    // ===================== device_mac =====================

    #[test]
    fn device_mac_follows_the_identifier_rule() {
        for raw in ["aa:bb:cc:00:00:01", "  AA:BB:CC:00:00:01 ", "aabbcc000001"] {
            assert_eq!(device_mac(&id(raw)).expect(raw), raw.trim());
        }
        for raw in [
            "",
            " ",
            "aa bb cc",
            "../aa",
            "/2.2/networks/n/devices/aa",
            "aa/bb",
            "-aa",
        ] {
            let error = device_mac(&id(raw)).expect_err(raw);
            assert_eq!(error.code, ErrorCode::InvalidArgument);
            assert_eq!(error.field.as_deref(), Some("device_mac"), "{raw:?}");
        }
    }

    // ===================== default network =====================

    #[test]
    fn network_entry_ids_come_from_id_then_url() {
        assert_eq!(
            network_entry_id(&json!({"id": "n1"})).as_deref(),
            Some("n1")
        );
        assert_eq!(
            network_entry_id(&json!({"id": 123})).as_deref(),
            Some("123")
        );
        assert_eq!(
            network_entry_id(&json!({"url": "/2.2/networks/n2"})).as_deref(),
            Some("n2")
        );
        assert_eq!(
            network_entry_id(&json!({"id": "", "url": "/2.2/networks/n3/"})).as_deref(),
            Some("n3")
        );
        assert_eq!(
            network_entry_id(&json!({"id": 0, "url": "/2.2/networks/n4"})).as_deref(),
            Some("n4")
        );
        assert_eq!(
            network_entry_id(&json!({"id": "bad id", "url": "/2.2/networks/n5"})).as_deref(),
            Some("n5")
        );
    }

    #[test]
    fn unusable_network_entries_have_no_id() {
        for entry in [
            json!({}),
            json!({"id": "../x"}),
            json!({"id": -1}),
            json!({"id": 1.5}),
            json!({"id": true}),
            json!({"url": ""}),
            json!({"url": "/"}),
            json!({"url": "/2.2/networks/%2e%2e"}),
            json!("n1"),
            json!(null),
        ] {
            assert_eq!(network_entry_id(&entry), None, "{entry}");
        }
    }

    #[test]
    fn exactly_one_network_is_used() {
        assert_eq!(
            pick_default_network(&[json!({"id": "network-0001", "name": "Home"})]).expect("one"),
            "network-0001"
        );
        assert_eq!(
            pick_default_network(&[json!({"url": "/2.2/networks/network-0007"})]).expect("one"),
            "network-0007"
        );
    }

    #[test]
    fn zero_networks_is_not_found() {
        let error = pick_default_network(&[]).expect_err("none");
        assert_eq!(error.code, ErrorCode::NotFound);
        assert_eq!(error.message, "no networks on this account");
        assert_eq!(error.field, None);
    }

    #[test]
    fn several_networks_list_each_id_and_name_and_pick_none() {
        let error = pick_default_network(&[
            json!({"id": "network-0001", "name": "Home"}),
            json!({"url": "/2.2/networks/network-0002", "name": "Cabin"}),
            json!({"id": 3}),
        ])
        .expect_err("ambiguous");
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.field.as_deref(), Some("network_id"));
        assert!(
            error.message.contains("network-0001 (Home)"),
            "{}",
            error.message
        );
        assert!(
            error.message.contains("network-0002 (Cabin)"),
            "{}",
            error.message
        );
        assert!(error.message.contains("3 (unnamed)"), "{}", error.message);
        assert!(error.message.contains("3 networks"));
    }

    #[test]
    fn network_names_in_messages_are_cleaned_and_bounded() {
        let long = "x".repeat(500);
        let error = pick_default_network(&[
            json!({"id": "n1", "name": "line1\nline2\u{7}"}),
            json!({"id": "n2", "name": long}),
        ])
        .expect_err("ambiguous");
        assert!(!error.message.contains('\n'));
        assert!(!error.message.contains('\u{7}'));
        assert!(error.message.len() < 400, "{}", error.message.len());
    }

    #[test]
    fn a_single_network_without_a_usable_id_is_an_unexpected_response() {
        let error = pick_default_network(&[json!({"name": "no id at all"})]).expect_err("no id");
        assert_eq!(error.code, ErrorCode::UpstreamError);
        let error = pick_default_network(&[json!({"id": "../x"})]).expect_err("hostile id");
        assert_eq!(error.code, ErrorCode::UpstreamError);
    }
}
