//! The tool error type and the mapping from rusteero's [`Error`].
//!
//! A failed tool call is an in-band result: `isError: true`, no `structuredContent`, and one text
//! block holding `{"error": {"code": ..., "message": ..., ...}}`. [`ToolError`] is that object.
//!
//! Rules enforced here:
//!
//! - The mapping branches only on [`Error`] variants, the error-code accessor and the error-group
//!   classifier. It never inspects message text.
//! - [`Error`] is `#[non_exhaustive]`; the wildcard arm maps future variants to `internal_error`.
//! - No rusteero `Display` string reaches the client. [`Error::Validation`] surfaces rusteero's
//!   catalogue message (it never echoes input); every other code carries eero-mcp's own fixed
//!   text. `Network` and `Api` are rendered from fixed text because their `Display` embeds the
//!   request URL or path (network, eero and device ids, query) and a redirect host.
//! - Raw error envelopes are never surfaced.

use rmcp::ErrorData;
use rmcp::handler::server::tool::IntoCallToolResult;
use rmcp::model::{CallToolResponse, CallToolResult, ContentBlock};
use rusteero::{Error, ErrorGroup, classify_error_code};
use serde_json::{Map, Value, json};

/// The stable error codes of the tool error object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The session is missing, expired or revoked.
    AuthenticationRequired,
    /// The data needs an eero Plus (or eero Secure) subscription.
    PremiumRequired,
    /// The eero is offline, or its hardware or firmware lacks the feature.
    FeatureUnavailable,
    /// eero rate-limited the request.
    RateLimited,
    /// The resource does not exist or is not supported.
    NotFound,
    /// The signed-in account lacks permission.
    AccessDenied,
    /// eero rejected this client version.
    ClientBlocked,
    /// A tool argument is invalid.
    InvalidArgument,
    /// The eero cloud API did not answer in time.
    Timeout,
    /// The eero cloud API could not be reached.
    NetworkError,
    /// The eero cloud API answered with an error or an unexpected response.
    UpstreamError,
    /// A credential store failed (not expected: no store is attached).
    CredentialError,
    /// Anything else.
    InternalError,
}

impl ErrorCode {
    /// The wire string of the code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationRequired => "authentication_required",
            Self::PremiumRequired => "premium_required",
            Self::FeatureUnavailable => "feature_unavailable",
            Self::RateLimited => "rate_limited",
            Self::NotFound => "not_found",
            Self::AccessDenied => "access_denied",
            Self::ClientBlocked => "client_blocked",
            Self::InvalidArgument => "invalid_argument",
            Self::Timeout => "timeout",
            Self::NetworkError => "network_error",
            Self::UpstreamError => "upstream_error",
            Self::CredentialError => "credential_error",
            Self::InternalError => "internal_error",
        }
    }
}

/// A failed tool call, rendered as the `{"error": {...}}` object.
///
/// Returning `Err(ToolError)` from a tool handler produces the `isError` result: the type
/// implements rmcp's `IntoCallToolResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError {
    /// The stable error code.
    pub code: ErrorCode,
    /// Fixed or catalogue text. Never a token, a request URL or raw input.
    pub message: String,
    /// Whole seconds to wait; only on `rate_limited`, when eero sent `Retry-After`.
    pub retry_after_seconds: Option<u64>,
    /// The tool parameter at fault; only on `invalid_argument`, when known.
    pub field: Option<String>,
    /// The eero HTTP status, when rusteero reports one.
    pub upstream_status: Option<u16>,
    /// eero's error-code string (such as `error.session.expired`), when rusteero reports one.
    pub upstream_code: Option<String>,
}

impl ToolError {
    /// A bare error with a code and a message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retry_after_seconds: None,
            field: None,
            upstream_status: None,
            upstream_code: None,
        }
    }

    /// An `invalid_argument` error naming the offending tool parameter.
    pub fn invalid_argument(field: &str, message: impl Into<String>) -> Self {
        let mut error = Self::new(ErrorCode::InvalidArgument, message);
        error.field = Some(field.to_owned());
        error
    }

    /// A `not_found` error that is not tied to an upstream response.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::NotFound, message)
    }

    /// An `upstream_error` for a response that did not have the expected shape.
    pub fn unexpected_response() -> Self {
        Self::new(ErrorCode::UpstreamError, UNEXPECTED_RESPONSE)
    }

    /// Rewords an `authentication_required` error after the credential re-read found a credential
    /// but it is the one that just failed. Without this, a call whose session was cleared by a
    /// concurrent failed refresh would say that no credential is available. Other codes are
    /// returned unchanged.
    #[must_use]
    pub(crate) fn with_credential_rejected(mut self) -> Self {
        if self.code == ErrorCode::AuthenticationRequired {
            AUTH_SESSION.clone_into(&mut self.message);
        }
        self
    }

    /// An `internal_error` with fixed text.
    pub fn internal() -> Self {
        Self::new(ErrorCode::InternalError, INTERNAL)
    }

    /// The `{"error": {...}}` object.
    pub fn to_value(&self) -> Value {
        let mut error = Map::new();
        error.insert("code".to_owned(), json!(self.code.as_str()));
        error.insert("message".to_owned(), json!(self.message));
        if let Some(seconds) = self.retry_after_seconds {
            error.insert("retry_after_seconds".to_owned(), json!(seconds));
        }
        if let Some(field) = &self.field {
            error.insert("field".to_owned(), json!(field));
        }
        if let Some(status) = self.upstream_status {
            error.insert("upstream_status".to_owned(), json!(status));
        }
        if let Some(code) = &self.upstream_code {
            error.insert("upstream_code".to_owned(), json!(code));
        }
        json!({ "error": Value::Object(error) })
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ToolError {}

impl IntoCallToolResult for ToolError {
    fn into_call_tool_result(self) -> Result<CallToolResponse, ErrorData> {
        let text = self.to_value().to_string();
        Ok(CallToolResult::error(vec![ContentBlock::text(text)]).into())
    }
}

const AUTH_SESSION: &str = "The eero session has expired, is invalid or was revoked. Log in again with eeroctl (or eero-api), or set a fresh RUSTEERO_SESSION_TOKEN and restart the server. Credentials stored by eeroctl or eero-api are re-read automatically, so no restart is needed for those.";
const AUTH_NO_CREDENTIAL: &str = "No eero credential is available. Log in with eeroctl (or eero-api), or set RUSTEERO_SESSION_TOKEN or EERO_MCP_SESSION_FILE. Credentials stored by eeroctl or eero-api are re-read automatically, so no restart is needed for those.";
const AUTH_GENERIC: &str = "The eero session is missing, expired or revoked. Log in again with eeroctl (or eero-api), or set a fresh RUSTEERO_SESSION_TOKEN and restart the server. Credentials stored by eeroctl or eero-api are re-read automatically, so no restart is needed for those.";
const PREMIUM: &str = "This data needs an eero Plus (or eero Secure) subscription on this network.";
const FEATURE_UNAVAILABLE: &str =
    "The eero is offline, or its hardware or firmware does not support this feature.";
const RATE_LIMITED: &str = "eero rate-limited this request. Wait before trying again; the server never retries rate limits.";
const NOT_FOUND: &str = "Resource not found, or not supported on this network or firmware.";
const ACCESS_DENIED: &str =
    "The signed-in account lacks permission for this data. This is not a session problem.";
const CLIENT_BLOCKED: &str = "eero rejected this client version; update eero-mcp.";
const MISSING_NETWORK: &str = "A network id is required; pass network_id.";
const TIMEOUT: &str = "The eero cloud API did not answer in time.";
const NETWORK: &str =
    "Could not reach the eero cloud API (connection, DNS or TLS failure). Try again later.";
const API_REDIRECT: &str = "The eero cloud API answered with a redirect, which is refused.";
const API_UNEXPECTED: &str = "The eero cloud API returned an unexpected response.";
const API_ERROR: &str = "The eero cloud API returned an error.";
const UNEXPECTED_RESPONSE: &str = API_UNEXPECTED;
const STORAGE: &str = "A credential store operation failed.";
const INTERNAL: &str = "An internal error occurred.";
/// Used instead of rusteero's text for the enumerated fields, whose validators quote the value.
const ENUM_VALUE: &str = "must be one of the documented values";

/// Maps a rusteero error to the tool error.
///
/// `id_param` names the tool parameter being validated when rusteero reports a validation error
/// on one of its id fields (`id`, `id_or_url`, `url`, `child`); with `None` those fields are
/// omitted from the result.
pub fn map_error(error: &Error, id_param: Option<&'static str>) -> ToolError {
    let mut mapped = match error {
        Error::Authentication { .. } => ToolError::new(
            ErrorCode::AuthenticationRequired,
            authentication_message(error),
        ),
        Error::PremiumRequired { .. } => ToolError::new(ErrorCode::PremiumRequired, PREMIUM),
        Error::FeatureUnavailable { .. } => {
            ToolError::new(ErrorCode::FeatureUnavailable, FEATURE_UNAVAILABLE)
        }
        Error::RateLimit { retry_after, .. } => {
            let mut mapped = ToolError::new(ErrorCode::RateLimited, RATE_LIMITED);
            // Rounded up: a wait of 29.4 s must not tell the agent to retry after 29.
            mapped.retry_after_seconds = retry_after.map(|wait| {
                wait.as_secs()
                    .saturating_add(u64::from(wait.subsec_nanos() > 0))
            });
            mapped
        }
        Error::NotFound { .. } => ToolError::new(ErrorCode::NotFound, NOT_FOUND),
        Error::AccessDenied { .. } => ToolError::new(ErrorCode::AccessDenied, ACCESS_DENIED),
        Error::ClientBlocked { .. } => ToolError::new(ErrorCode::ClientBlocked, CLIENT_BLOCKED),
        Error::Validation { field, message, .. } => validation(field, message, id_param),
        Error::MissingNetworkId => ToolError::invalid_argument("network_id", MISSING_NETWORK),
        Error::Timeout => ToolError::new(ErrorCode::Timeout, TIMEOUT),
        Error::Network(_) => ToolError::new(ErrorCode::NetworkError, NETWORK),
        Error::Api { status, .. } => ToolError::new(ErrorCode::UpstreamError, api_message(*status)),
        Error::Json(_) => ToolError::new(ErrorCode::UpstreamError, API_UNEXPECTED),
        Error::Storage(_) => ToolError::new(ErrorCode::CredentialError, STORAGE),
        _ => ToolError::new(ErrorCode::InternalError, INTERNAL),
    };
    mapped.upstream_status = error.status();
    mapped.upstream_code = error
        .error_code()
        .filter(|code| looks_like_catalogue_code(code))
        .map(str::to_owned);
    mapped
}

/// The longest `upstream_code` relayed to the agent.
const MAX_UPSTREAM_CODE_LEN: usize = 100;

/// Whether `code` has the shape of one of eero's catalogue codes, such as `error.session.expired`:
/// short, lowercase, digits, dots, underscores and hyphens. rusteero reports `meta.error` from the
/// response body verbatim, so free text or a reflected value must not reach the agent.
fn looks_like_catalogue_code(code: &str) -> bool {
    (1..=MAX_UPSTREAM_CODE_LEN).contains(&code.len())
        && code.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// The wording of an authentication failure; the code never changes.
fn authentication_message(error: &Error) -> &'static str {
    match classify_error_code(error.error_code()) {
        Some(ErrorGroup::Session | ErrorGroup::SessionRefresh) => AUTH_SESSION,
        _ if error.status().is_none() && error.error_code().is_none() => AUTH_NO_CREDENTIAL,
        _ => AUTH_GENERIC,
    }
}

/// Fixed text by status class, never rusteero's `Display`.
fn api_message(status: u16) -> &'static str {
    match status {
        300..=399 => API_REDIRECT,
        200..=299 => API_UNEXPECTED,
        _ => API_ERROR,
    }
}

/// Maps a rusteero validation error: the reported field becomes the tool parameter, and the
/// message is rusteero's catalogue text (which never echoes input).
fn validation(field: &str, message: &str, id_param: Option<&'static str>) -> ToolError {
    let parameter = match field {
        "id" | "id_or_url" | "url" | "child" => id_param,
        "cadence" => Some("cadence"),
        "band" => Some("band"),
        "granularity" => Some("granularity"),
        "busy_threshold" => Some("busy_threshold"),
        // `request` is a 400 from eero; `link`, `path`, `template` and others are internal.
        _ => None,
    };
    // rusteero's cadence and band validators quote the rejected value. Enumerations are enforced
    // at deserialisation, so this is unreachable in practice; the fixed text keeps it that way
    // even if it were reached.
    let message = if matches!(parameter, Some("cadence" | "band")) {
        ENUM_VALUE
    } else {
        message
    };
    let mut mapped = ToolError::new(ErrorCode::InvalidArgument, message);
    mapped.field = parameter.map(str::to_owned);
    mapped
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rusteero::StorageError;
    use serde_json::json;

    use super::*;

    fn authentication(status: Option<u16>, code: Option<&str>) -> Error {
        Error::Authentication {
            message: "ignored".to_owned(),
            envelope: Some(json!({"meta": {"error": "leaky"}})),
            error_code: code.map(str::to_owned),
            status,
        }
    }

    fn api_error(status: u16, code: Option<&str>) -> Error {
        Error::Api {
            status,
            message: "rusteero text with /2.2/networks/network-0001/devices/device-0001".to_owned(),
            envelope: Some(json!({"data": {"password": "hunter2"}})),
            error_code: code.map(str::to_owned),
            url: Some("http://mock.test/2.2/networks/network-0001".to_owned()),
        }
    }

    fn validation_error(field: &str, message: &str) -> Error {
        Error::Validation {
            field: field.to_owned(),
            message: message.to_owned(),
            envelope: None,
            error_code: None,
        }
    }

    #[test]
    fn a_found_but_rejected_credential_is_never_reported_as_missing() {
        let missing = map_error(&authentication(None, None), None);
        assert_eq!(missing.message, AUTH_NO_CREDENTIAL);
        let rejected = missing.with_credential_rejected();
        assert_eq!(rejected.code, ErrorCode::AuthenticationRequired);
        assert_eq!(rejected.message, AUTH_SESSION);
        let plain_401 =
            map_error(&authentication(Some(401), None), None).with_credential_rejected();
        assert_eq!(plain_401.message, AUTH_SESSION);
        // Other codes keep their text.
        let not_found = ToolError::not_found("gone").with_credential_rejected();
        assert_eq!(not_found.message, "gone");
    }

    #[test]
    fn code_strings_are_the_documented_set() {
        let all = [
            (ErrorCode::AuthenticationRequired, "authentication_required"),
            (ErrorCode::PremiumRequired, "premium_required"),
            (ErrorCode::FeatureUnavailable, "feature_unavailable"),
            (ErrorCode::RateLimited, "rate_limited"),
            (ErrorCode::NotFound, "not_found"),
            (ErrorCode::AccessDenied, "access_denied"),
            (ErrorCode::ClientBlocked, "client_blocked"),
            (ErrorCode::InvalidArgument, "invalid_argument"),
            (ErrorCode::Timeout, "timeout"),
            (ErrorCode::NetworkError, "network_error"),
            (ErrorCode::UpstreamError, "upstream_error"),
            (ErrorCode::CredentialError, "credential_error"),
            (ErrorCode::InternalError, "internal_error"),
        ];
        for (code, text) in all {
            assert_eq!(code.as_str(), text);
        }
    }

    #[test]
    fn authentication_maps_with_status_and_code() {
        let mapped = map_error(
            &authentication(Some(401), Some("error.session.expired")),
            None,
        );
        assert_eq!(mapped.code, ErrorCode::AuthenticationRequired);
        assert_eq!(mapped.upstream_status, Some(401));
        assert_eq!(
            mapped.upstream_code.as_deref(),
            Some("error.session.expired")
        );
        assert_eq!(mapped.message, AUTH_SESSION);
    }

    #[test]
    fn authentication_wording_is_refined_by_group_but_the_code_never_changes() {
        let no_credential = map_error(&authentication(None, None), None);
        assert_eq!(no_credential.code, ErrorCode::AuthenticationRequired);
        assert_eq!(no_credential.message, AUTH_NO_CREDENTIAL);
        assert_eq!(no_credential.upstream_status, None);

        let refresh = map_error(
            &authentication(Some(401), Some("error.session.refresh")),
            None,
        );
        assert_eq!(refresh.message, AUTH_SESSION);

        let plain_401 = map_error(&authentication(Some(401), None), None);
        assert_eq!(plain_401.code, ErrorCode::AuthenticationRequired);
        assert_eq!(plain_401.message, AUTH_GENERIC);

        let verification = map_error(
            &authentication(Some(401), Some("error.verification.invalid")),
            None,
        );
        assert_eq!(verification.code, ErrorCode::AuthenticationRequired);
        assert_eq!(verification.message, AUTH_GENERIC);
    }

    #[test]
    fn premium_and_feature_unavailable_map_with_their_status() {
        let premium = map_error(
            &Error::PremiumRequired {
                status: Some(403),
                message: "m".to_owned(),
                envelope: None,
                error_code: Some("error.premium.user_not_subscribed".to_owned()),
            },
            None,
        );
        assert_eq!(premium.code, ErrorCode::PremiumRequired);
        assert_eq!(premium.upstream_status, Some(403));
        assert_eq!(
            premium.upstream_code.as_deref(),
            Some("error.premium.user_not_subscribed")
        );

        let unavailable = map_error(
            &Error::FeatureUnavailable {
                status: None,
                message: "m".to_owned(),
                envelope: None,
                error_code: Some("error.eero.offline".to_owned()),
            },
            None,
        );
        assert_eq!(unavailable.code, ErrorCode::FeatureUnavailable);
        assert_eq!(unavailable.upstream_status, None);
    }

    #[test]
    fn retry_after_is_rounded_up_never_down() {
        let seconds = |wait: Duration| {
            map_error(
                &Error::RateLimit {
                    message: "m".to_owned(),
                    retry_after: Some(wait),
                    envelope: None,
                    error_code: None,
                    status: Some(429),
                },
                None,
            )
            .retry_after_seconds
        };
        assert_eq!(seconds(Duration::from_millis(29_400)), Some(30));
        assert_eq!(
            seconds(Duration::from_millis(1)),
            Some(1),
            "never zero for a real wait"
        );
        assert_eq!(
            seconds(Duration::from_secs(30)),
            Some(30),
            "whole seconds are exact"
        );
        assert_eq!(seconds(Duration::ZERO), Some(0));
        assert_eq!(seconds(Duration::MAX), Some(u64::MAX), "saturates");
    }

    #[test]
    fn upstream_code_is_relayed_only_when_it_looks_like_a_catalogue_code() {
        for good in [
            "error.session.expired",
            "error.premium.user_not_subscribed",
            "error.app.version.blocked",
            "error.rate.limit",
            "x",
        ] {
            let mapped = map_error(&api_error(500, Some(good)), None);
            assert_eq!(mapped.upstream_code.as_deref(), Some(good));
        }
        let long = "e".repeat(MAX_UPSTREAM_CODE_LEN + 1);
        let exact = "e".repeat(MAX_UPSTREAM_CODE_LEN);
        for bad in [
            "",
            "Internal error for user@example.com",
            "contains space",
            "UPPER.CASE",
            "line\nbreak",
            "error/with/slash",
            "caf\u{e9}",
            long.as_str(),
        ] {
            let mapped = map_error(&api_error(500, Some(bad)), None);
            assert_eq!(mapped.upstream_code, None, "{bad:?}");
            assert_eq!(
                mapped.upstream_status,
                Some(500),
                "the status is still relayed"
            );
            assert!(!mapped.to_value().to_string().contains("user@example.com"));
        }
        let mapped = map_error(&api_error(500, Some(&exact)), None);
        assert_eq!(mapped.upstream_code.as_deref(), Some(exact.as_str()));
    }

    #[test]
    fn an_unrecognised_code_still_refines_nothing_but_the_wording() {
        // The wording is chosen from the raw code; relaying is filtered separately.
        let mapped = map_error(&authentication(Some(401), Some("Free Text!")), None);
        assert_eq!(mapped.code, ErrorCode::AuthenticationRequired);
        assert_eq!(mapped.upstream_code, None);
        assert_eq!(mapped.upstream_status, Some(401));
    }

    #[test]
    fn rate_limit_carries_whole_seconds() {
        let with_header = map_error(
            &Error::RateLimit {
                message: "m".to_owned(),
                retry_after: Some(Duration::from_secs(30)),
                envelope: None,
                error_code: Some("error.rate.limit".to_owned()),
                status: Some(429),
            },
            None,
        );
        assert_eq!(with_header.code, ErrorCode::RateLimited);
        assert_eq!(with_header.retry_after_seconds, Some(30));
        assert_eq!(with_header.upstream_status, Some(429));

        let without_header = map_error(
            &Error::RateLimit {
                message: "m".to_owned(),
                retry_after: None,
                envelope: None,
                error_code: None,
                status: Some(429),
            },
            None,
        );
        assert_eq!(without_header.retry_after_seconds, None);
        assert!(
            without_header.to_value()["error"]
                .get("retry_after_seconds")
                .is_none()
        );
    }

    #[test]
    fn not_found_access_denied_and_client_blocked_map_by_variant() {
        let fields = |status| (status, "m".to_owned(), None::<Value>, None::<String>);
        let (status, message, envelope, error_code) = fields(404);
        let not_found = map_error(
            &Error::NotFound {
                status,
                message,
                envelope,
                error_code,
            },
            None,
        );
        assert_eq!(not_found.code, ErrorCode::NotFound);
        assert_eq!(not_found.upstream_status, Some(404));

        let denied = map_error(
            &Error::AccessDenied {
                status: 403,
                message: "m".to_owned(),
                envelope: None,
                error_code: Some("error.access.denied".to_owned()),
            },
            None,
        );
        assert_eq!(denied.code, ErrorCode::AccessDenied);
        assert_eq!(denied.upstream_code.as_deref(), Some("error.access.denied"));

        let blocked = map_error(
            &Error::ClientBlocked {
                status: 400,
                message: "m".to_owned(),
                envelope: None,
                error_code: Some("error.app.version.blocked".to_owned()),
            },
            None,
        );
        assert_eq!(blocked.code, ErrorCode::ClientBlocked);
    }

    #[test]
    fn api_is_rendered_from_the_status_class_only() {
        let redirect = map_error(&api_error(302, None), None);
        assert_eq!(redirect.code, ErrorCode::UpstreamError);
        assert_eq!(redirect.message, API_REDIRECT);
        assert_eq!(redirect.upstream_status, Some(302));

        let unexpected = map_error(&api_error(200, None), None);
        assert_eq!(unexpected.message, API_UNEXPECTED);

        let server = map_error(&api_error(500, Some("error.something")), None);
        assert_eq!(server.message, API_ERROR);
        assert_eq!(server.upstream_status, Some(500));
        assert_eq!(server.upstream_code.as_deref(), Some("error.something"));

        let plain_403 = map_error(&api_error(403, None), None);
        assert_eq!(plain_403.code, ErrorCode::UpstreamError);
        assert_eq!(plain_403.upstream_status, Some(403));
    }

    #[test]
    fn nothing_from_rusteero_text_reaches_the_rendered_error() {
        for error in [
            api_error(302, None),
            api_error(500, None),
            authentication(Some(401), Some("error.session.expired")),
        ] {
            let rendered = map_error(&error, None).to_value().to_string();
            for leak in [
                "network-0001",
                "device-0001",
                "mock.test",
                "hunter2",
                "leaky",
                "/2.2/",
            ] {
                assert!(!rendered.contains(leak), "{leak} leaked into {rendered}");
            }
        }
    }

    #[test]
    fn json_storage_timeout_and_missing_network_have_fixed_mappings() {
        let json_error = serde_json::from_str::<Value>("not json").expect_err("invalid json");
        let mapped = map_error(&Error::Json(json_error), None);
        assert_eq!(mapped.code, ErrorCode::UpstreamError);
        assert_eq!(mapped.message, API_UNEXPECTED);

        let storage = map_error(&Error::Storage(StorageError::Empty), None);
        assert_eq!(storage.code, ErrorCode::CredentialError);
        assert_eq!(storage.message, STORAGE);

        let timeout = map_error(&Error::Timeout, None);
        assert_eq!(timeout.code, ErrorCode::Timeout);
        assert_eq!(timeout.upstream_status, None);

        let missing = map_error(&Error::MissingNetworkId, None);
        assert_eq!(missing.code, ErrorCode::InvalidArgument);
        assert_eq!(missing.field.as_deref(), Some("network_id"));
    }

    #[test]
    fn validation_maps_rusteero_fields_to_tool_parameters() {
        for field in ["id", "id_or_url", "url", "child"] {
            let mapped = map_error(
                &validation_error(field, "must be a single path segment identifier"),
                Some("device_id"),
            );
            assert_eq!(mapped.code, ErrorCode::InvalidArgument);
            assert_eq!(mapped.field.as_deref(), Some("device_id"), "{field}");
            assert_eq!(mapped.message, "must be a single path segment identifier");
        }
        for field in ["granularity", "busy_threshold"] {
            let mapped = map_error(&validation_error(field, "must be a positive integer"), None);
            assert_eq!(mapped.field.as_deref(), Some(field));
            assert_eq!(mapped.message, "must be a positive integer");
        }
    }

    #[test]
    fn validation_fields_without_a_tool_parameter_are_omitted() {
        let id_without_param = map_error(&validation_error("id", "m"), None);
        assert_eq!(id_without_param.field, None);
        for field in ["request", "link", "path", "template", "something_else"] {
            let mapped = map_error(&validation_error(field, "m"), Some("network_id"));
            assert_eq!(mapped.field, None, "{field}");
            assert_eq!(mapped.code, ErrorCode::InvalidArgument);
        }
        assert!(
            map_error(&validation_error("request", "m"), None).to_value()["error"]
                .get("field")
                .is_none()
        );
    }

    #[test]
    fn enumerated_fields_never_echo_rusteeros_text() {
        for field in ["cadence", "band"] {
            let mapped = map_error(
                &validation_error(field, "must be one of ['daily', 'hourly'], got 'weekly'"),
                None,
            );
            assert_eq!(mapped.field.as_deref(), Some(field));
            assert_eq!(mapped.message, ENUM_VALUE);
            assert!(!mapped.message.contains("weekly"));
        }
    }

    #[test]
    fn to_value_has_only_the_documented_members() {
        let mut error = ToolError::invalid_argument("network_id", "bad");
        error.upstream_status = Some(400);
        error.upstream_code = Some("error.form.errors".to_owned());
        error.retry_after_seconds = Some(7);
        let value = error.to_value();
        let object = value.as_object().expect("object");
        assert_eq!(object.len(), 1);
        let inner = value["error"].as_object().expect("error object");
        let mut keys: Vec<_> = inner.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "code",
                "field",
                "message",
                "retry_after_seconds",
                "upstream_code",
                "upstream_status"
            ]
        );
        assert_eq!(value["error"]["code"], "invalid_argument");
    }

    #[test]
    fn into_call_tool_result_is_an_in_band_error_without_structured_content() {
        let response = ToolError::not_found("no networks on this account")
            .into_call_tool_result()
            .expect("in-band");
        let CallToolResponse::Complete(result) = response else {
            panic!("expected a complete result");
        };
        assert_eq!(result.is_error, Some(true));
        assert!(result.structured_content.is_none());
        assert_eq!(result.content.len(), 1);
        let text = result.content[0].as_text().expect("text block");
        let parsed: Value = serde_json::from_str(&text.text).expect("json");
        assert_eq!(parsed["error"]["code"], "not_found");
        assert_eq!(parsed["error"]["message"], "no networks on this account");
    }

    #[test]
    fn display_names_the_code_and_the_message() {
        let text = ToolError::internal().to_string();
        assert!(text.starts_with("internal_error: "));
    }
}
