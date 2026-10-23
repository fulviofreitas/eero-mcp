//! The success object, list unwrapping and the device summary projection.
//!
//! Every success leaves through [`ToolOutput`], whose constructors always redact
//! ([`crate::redact`]). The rmcp `Json` wrapper turns it into `structuredContent` plus one text
//! block holding the same object as compact JSON, and publishes its schema as the tool's
//! `outputSchema`.

use rusteero::Envelope;
use rusteero::util::id_from_url;
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::params::{Cadence, DetailMode, InsightType, drop_default, non_negative};
use crate::redact;
use crate::window::Window;

/// The effective time window of a windowed tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[schemars(inline)]
pub struct WindowEcho {
    /// Start of the window actually queried (RFC 3339).
    pub start: String,
    /// End of the window actually queried (RFC 3339).
    pub end: String,
    /// Bucket size used (usage and insight tools).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Cadence", transform = drop_default)]
    pub cadence: Option<Cadence>,
    /// IANA time zone passed to eero, when one was given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String", transform = drop_default)]
    pub timezone: Option<String>,
    /// Insight category queried (insight tools).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "InsightType", transform = drop_default)]
    pub insight_type: Option<InsightType>,
}

impl WindowEcho {
    /// The echo of an effective window, with no extras.
    pub fn new(window: Window) -> Self {
        Self {
            start: window.start,
            end: window.end,
            cadence: None,
            timezone: None,
            insight_type: None,
        }
    }

    /// Adds the cadence.
    #[must_use]
    pub fn cadence(mut self, cadence: Cadence) -> Self {
        self.cadence = Some(cadence);
        self
    }

    /// Adds the time zone, when one was given.
    #[must_use]
    pub fn timezone(mut self, timezone: Option<&str>) -> Self {
        self.timezone = timezone.map(str::to_owned);
        self
    }

    /// Adds the insight type.
    #[must_use]
    pub fn insight_type(mut self, insight_type: InsightType) -> Self {
        self.insight_type = Some(insight_type);
        self
    }
}

/// The success object every tool returns.
// The fields are private on purpose (a plain comment: a doc comment here would be published in the
// output schema): the only way to build one is through the constructors, which always redact
// `data`, and the `with_*` builders. A handler cannot assign a projection to `data` afterwards and
// skip redaction.
// The field docs are published as schema descriptions for agents: no markdown backticks there, and
// the literal "[REDACTED]" is not an intra-doc link.
#[allow(clippy::doc_markdown, rustdoc::broken_intra_doc_links)]
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
pub struct ToolOutput {
    /// What eero returned, exactly as eero sent it, with secret values (Wi-Fi and guest
    /// passwords, keys, tokens) replaced by "[REDACTED]". list_networks returns the unwrapped
    /// list of network entries; list_devices in summary mode returns the projected device list.
    data: Value,
    /// The network that was queried, as a bare id. Present on network-scoped tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String", transform = drop_default)]
    network_id: Option<String>,
    /// The server time eero reported for this response, when it sent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "String", transform = drop_default)]
    server_time: Option<String>,
    /// The effective time window. Present on get_channel_utilization and the usage and insight
    /// tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "WindowEcho", transform = drop_default)]
    window: Option<WindowEcho>,
    /// The detail mode used: summary or full. Present on list_devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "DetailMode", transform = drop_default)]
    detail: Option<DetailMode>,
    /// The number of devices returned. Present on list_devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(with = "u64", transform = non_negative)]
    count: Option<u64>,
}

impl ToolOutput {
    /// An output over `data`, redacted. Prefer [`ToolOutput::from_envelope`].
    pub fn from_value(data: &Value) -> Self {
        Self {
            data: redact::redacted(data),
            network_id: None,
            server_time: None,
            window: None,
            detail: None,
            count: None,
        }
    }

    /// The envelope's data, redacted, plus the envelope's server time. The rest of the envelope
    /// meta (codes, server bookkeeping) is dropped.
    pub fn from_envelope(envelope: &Envelope) -> Self {
        let mut output = Self::from_value(envelope.data());
        output.server_time = envelope.meta().server_time;
        output
    }

    /// Like [`ToolOutput::from_envelope`] but over replacement `data` (a projection or an
    /// unwrapped list), still redacted.
    pub fn from_envelope_with_data(envelope: &Envelope, data: &Value) -> Self {
        let mut output = Self::from_value(data);
        output.server_time = envelope.meta().server_time;
        output
    }

    /// Records the network actually queried.
    #[must_use]
    pub fn with_network(mut self, network_id: impl Into<String>) -> Self {
        self.network_id = Some(network_id.into());
        self
    }

    /// Records the effective window.
    #[must_use]
    pub fn with_window(mut self, window: WindowEcho) -> Self {
        self.window = Some(window);
        self
    }

    /// The (redacted) data.
    pub fn data(&self) -> &Value {
        &self.data
    }

    /// The network that was queried, when the tool is network-scoped.
    pub fn network_id(&self) -> Option<&str> {
        self.network_id.as_deref()
    }

    /// The server time eero reported, when it sent one.
    pub fn server_time(&self) -> Option<&str> {
        self.server_time.as_deref()
    }

    /// The effective time window, on the windowed tools.
    pub fn window(&self) -> Option<&WindowEcho> {
        self.window.as_ref()
    }

    /// The detail mode, on `list_devices`.
    pub fn detail(&self) -> Option<DetailMode> {
        self.detail
    }

    /// The number of devices returned, on `list_devices`.
    pub fn count(&self) -> Option<u64> {
        self.count
    }

    /// Records the detail mode and the number of devices returned.
    #[must_use]
    pub fn with_detail(mut self, detail: DetailMode, count: usize) -> Self {
        self.detail = Some(detail);
        self.count = Some(u64::try_from(count).unwrap_or(u64::MAX));
        self
    }
}

/// Unwraps the network list from any of eero's three shapes: a bare array, a `networks` array
/// inside `data`, or a `data` array inside `data` (rusteero's account fallback synthesises the
/// `networks` shape). As in rusteero, a non-empty `networks` array wins over `data`; any other
/// shape is an empty list.
pub fn unwrap_network_list(data: &Value) -> Vec<Value> {
    match data {
        Value::Array(items) => items.clone(),
        Value::Object(map) => ["networks", "data"]
            .iter()
            .filter_map(|key| map.get(*key).and_then(Value::as_array))
            .find(|items| !items.is_empty())
            .cloned()
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// The device array of a device-list `data`: a bare array, or the first array under `devices` or
/// `data`. An empty array is a list (an account with no devices), not an unrecognised shape.
/// `None` when the data has no recognisable list.
pub fn device_list(data: &Value) -> Option<&Vec<Value>> {
    match data {
        Value::Array(items) => Some(items),
        Value::Object(map) => ["devices", "data"]
            .iter()
            .find_map(|key| map.get(*key).and_then(Value::as_array)),
        _ => None,
    }
}

/// The keys of a device that the summary copies unchanged.
const COPIED: [&str; 20] = [
    "url",
    "mac",
    "nickname",
    "hostname",
    "display_name",
    "manufacturer",
    "device_type",
    "model_name",
    "ip",
    "ips",
    "connected",
    "wireless",
    "connection_type",
    "blocked",
    "blacklisted",
    "paused",
    "prioritized",
    "is_guest",
    "last_active",
    "first_active",
];

/// Reduces an object to the listed keys that are present; a non-object is copied unchanged.
/// `None` when an object has none of the keys (nothing worth emitting).
fn reduce(value: &Value, keys: &[&str]) -> Option<Value> {
    match value {
        Value::Object(map) => {
            let reduced: Map<String, Value> = keys
                .iter()
                .filter_map(|key| map.get(*key).map(|v| ((*key).to_owned(), v.clone())))
                .collect();
            (!reduced.is_empty()).then_some(Value::Object(reduced))
        }
        other => Some(other.clone()),
    }
}

/// Projects one device to its summary. Only keys present on the device are emitted; values are
/// copied unchanged. A non-object device is returned as is.
///
/// | Emitted key | Taken from |
/// |---|---|
/// | `id` | `id`; when absent or null, the last segment of `url` (eero devices usually have no id) |
/// | `url`, `mac`, `nickname`, `hostname`, `display_name`, `manufacturer`, `device_type`, `model_name`, `ip`, `ips`, `connected`, `wireless`, `connection_type` | the same keys |
/// | `interface` | `interface`, reduced to `frequency` and `frequency_unit` |
/// | `source` | `source`, reduced to `location` and `url` (the eero the device is attached to) |
/// | `profile` | `profile`, reduced to `name` and `url` |
/// | `blocked`, `blacklisted` | each under its own key when present |
/// | `paused`, `prioritized`, `is_guest`, `last_active`, `first_active` | the same keys |
pub fn device_summary(device: &Value) -> Value {
    let Value::Object(map) = device else {
        return device.clone();
    };
    let mut summary = Map::new();

    match map.get("id") {
        Some(id) if !id.is_null() => {
            summary.insert("id".to_owned(), id.clone());
        }
        _ => {
            if let Some(url) = map.get("url").and_then(Value::as_str)
                && let Ok(id) = id_from_url(url)
            {
                summary.insert("id".to_owned(), Value::String(id));
            }
        }
    }

    for key in COPIED {
        if let Some(value) = map.get(key) {
            summary.insert(key.to_owned(), value.clone());
        }
    }
    for (key, keep) in [
        ("interface", &["frequency", "frequency_unit"][..]),
        ("source", &["location", "url"][..]),
        ("profile", &["name", "url"][..]),
    ] {
        if let Some(reduced) = map.get(key).and_then(|value| reduce(value, keep)) {
            summary.insert(key.to_owned(), reduced);
        }
    }
    Value::Object(summary)
}

/// Projects a device list to summaries. `None` when `data` has no recognisable list, so the tool
/// can fall back to the raw (redacted) data rather than report zero devices.
pub fn summarize_devices(data: &Value) -> Option<Vec<Value>> {
    device_list(data).map(|devices| devices.iter().map(device_summary).collect())
}

#[cfg(test)]
mod tests {
    use rmcp::handler::server::common::schema_for_output;
    use serde_json::json;

    use super::*;

    fn envelope(value: Value) -> Envelope {
        Envelope::from_value(value)
    }

    // ===================== ToolOutput =====================

    #[test]
    fn from_envelope_keeps_data_and_server_time_and_drops_the_rest_of_meta() {
        let out = ToolOutput::from_envelope(&envelope(json!({
            "meta": {"code": 200, "server_time": "2026-01-01T00:00:10Z", "extra": "dropped"},
            "data": {"name": "Example-Network"}
        })));
        let value = serde_json::to_value(&out).expect("serialize");
        assert_eq!(
            value,
            json!({"data": {"name": "Example-Network"}, "server_time": "2026-01-01T00:00:10Z"})
        );
    }

    #[test]
    fn server_time_is_absent_when_eero_sends_none() {
        let out = ToolOutput::from_envelope(&envelope(json!({"meta": {"code": 200}, "data": []})));
        let value = serde_json::to_value(&out).expect("serialize");
        assert_eq!(value, json!({"data": []}));
        assert!(value.get("server_time").is_none());
    }

    #[test]
    fn a_missing_data_member_is_null() {
        let out = ToolOutput::from_envelope(&envelope(json!({"meta": {"code": 200}})));
        assert_eq!(out.data, Value::Null);
    }

    #[test]
    fn every_constructor_redacts() {
        let data = json!({"guest_network": {"password": "guestpass000", "name": "Guest"}});
        let env = envelope(json!({"meta": {}, "data": data}));
        for out in [
            ToolOutput::from_envelope(&env),
            ToolOutput::from_value(&data),
            ToolOutput::from_envelope_with_data(&env, &data),
        ] {
            assert_eq!(out.data["guest_network"]["password"], redact::REDACTED);
            assert_eq!(out.data["guest_network"]["name"], "Guest");
        }
    }

    #[test]
    fn builders_add_network_window_detail_and_count() {
        let window = WindowEcho::new(Window {
            start: "2026-10-16T00:00:00Z".to_owned(),
            end: "2026-10-23T00:00:00Z".to_owned(),
        })
        .cadence(Cadence::Hourly)
        .timezone(Some("America/Los_Angeles"))
        .insight_type(InsightType::Adblock);
        let out = ToolOutput::from_value(&json!([]))
            .with_network("network-0001")
            .with_window(window)
            .with_detail(DetailMode::Summary, 3);
        let value = serde_json::to_value(&out).expect("serialize");
        assert_eq!(
            value,
            json!({
                "data": [],
                "network_id": "network-0001",
                "window": {
                    "start": "2026-10-16T00:00:00Z",
                    "end": "2026-10-23T00:00:00Z",
                    "cadence": "hourly",
                    "timezone": "America/Los_Angeles",
                    "insight_type": "adblock"
                },
                "detail": "summary",
                "count": 3
            })
        );
    }

    #[test]
    fn window_echo_omits_what_does_not_apply() {
        let window = WindowEcho::new(Window {
            start: "a".to_owned(),
            end: "b".to_owned(),
        })
        .timezone(None);
        let value = serde_json::to_value(window).expect("serialize");
        assert_eq!(value, json!({"start": "a", "end": "b"}));
    }

    #[test]
    fn the_output_schema_is_an_object_with_typed_optional_members() {
        let schema = Value::Object((*schema_for_output::<ToolOutput>()).clone());
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["required"], json!(["data"]));
        let text = schema.to_string();
        assert!(!text.contains("\"default\""), "{text}");
        assert!(!text.contains("\"null\""), "{text}");
        let properties = schema["properties"].as_object().expect("properties");
        let mut names: Vec<_> = properties.keys().map(String::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "count",
                "data",
                "detail",
                "network_id",
                "server_time",
                "window"
            ]
        );
        for (name, property) in properties {
            assert!(property["description"].is_string(), "{name} is described");
        }
        assert_eq!(properties["network_id"]["type"], "string");
        assert_eq!(properties["count"]["type"], "integer");
        assert_eq!(properties["count"]["minimum"], 0);
        assert!(
            properties["count"].get("format").is_none(),
            "no non-standard integer format"
        );
        assert_eq!(properties["window"]["type"], "object");
        assert_eq!(properties["detail"]["type"], "string");
    }

    // ===================== list unwrapping =====================

    #[test]
    fn unwraps_a_bare_array() {
        let data = json!([{"id": "n1"}, {"id": "n2"}]);
        assert_eq!(unwrap_network_list(&data).len(), 2);
    }

    #[test]
    fn unwraps_a_networks_array_inside_data() {
        let data = json!({"networks": [{"id": "n1"}]});
        assert_eq!(unwrap_network_list(&data), vec![json!({"id": "n1"})]);
    }

    #[test]
    fn unwraps_a_data_array_inside_data() {
        let data = json!({"data": [{"id": "n1"}, {"id": "n2"}]});
        assert_eq!(unwrap_network_list(&data).len(), 2);
    }

    #[test]
    fn a_non_empty_networks_array_wins_over_data() {
        let data = json!({"networks": [{"id": "from-networks"}], "data": [{"id": "from-data"}]});
        assert_eq!(
            unwrap_network_list(&data),
            vec![json!({"id": "from-networks"})]
        );
        let data = json!({"networks": [], "data": [{"id": "from-data"}]});
        assert_eq!(unwrap_network_list(&data), vec![json!({"id": "from-data"})]);
    }

    #[test]
    fn any_other_shape_is_an_empty_list() {
        for data in [
            json!(null),
            json!({}),
            json!("networks"),
            json!(7),
            json!({"networks": "x"}),
            json!({"networks": null, "data": {}}),
            json!({"networks": [], "data": []}),
            json!([]),
        ] {
            assert!(unwrap_network_list(&data).is_empty(), "{data}");
        }
    }

    // ===================== device summary =====================

    #[test]
    fn the_summary_copies_only_present_keys() {
        let device = json!({
            "url": "/2.2/networks/network-0001/devices/device-0001",
            "mac": "AA:BB:CC:00:00:01",
            "manufacturer": "Test Manufacturer",
            "hostname": "test-phone",
            "nickname": "Test Phone",
            "ip": "192.168.4.101",
            "connected": true,
            "blocked": false,
            "prioritized": false,
            "wireless": true,
            "connection_type": "wireless",
            "source": {"location": "Living Room"},
            "serial": "dropped",
            "usage": {"down": 1}
        });
        assert_eq!(
            device_summary(&device),
            json!({
                "id": "device-0001",
                "url": "/2.2/networks/network-0001/devices/device-0001",
                "mac": "AA:BB:CC:00:00:01",
                "manufacturer": "Test Manufacturer",
                "hostname": "test-phone",
                "nickname": "Test Phone",
                "ip": "192.168.4.101",
                "connected": true,
                "wireless": true,
                "connection_type": "wireless",
                "blocked": false,
                "source": {"location": "Living Room"},
                "prioritized": false
            })
        );
    }

    #[test]
    fn id_comes_from_the_id_key_when_present_else_the_url_tail() {
        assert_eq!(
            device_summary(&json!({"id": "explicit", "url": "/2.2/x/tail"}))["id"],
            "explicit"
        );
        assert_eq!(device_summary(&json!({"id": 42}))["id"], 42);
        assert_eq!(
            device_summary(&json!({"id": null, "url": "/2.2/x/tail/"}))["id"],
            "tail"
        );
        assert_eq!(device_summary(&json!({"url": "/2.2/x/tail"}))["id"], "tail");
        assert!(device_summary(&json!({"mac": "aa"})).get("id").is_none());
        assert!(device_summary(&json!({"url": "/"})).get("id").is_none());
        assert!(device_summary(&json!({"url": 7})).get("id").is_none());
    }

    #[test]
    fn nulls_are_kept_because_values_are_copied_unchanged() {
        let summary = device_summary(&json!({"nickname": null, "ip": "192.168.4.102"}));
        assert_eq!(summary["nickname"], Value::Null);
        assert!(
            summary
                .as_object()
                .expect("object")
                .contains_key("nickname")
        );
    }

    #[test]
    fn interface_source_and_profile_are_reduced() {
        let summary = device_summary(&json!({
            "interface": {"frequency": "5", "frequency_unit": "GHz", "tx_rate": 1, "rx_rate": 2},
            "source": {"location": "Kitchen", "url": "/2.2/eeros/eero-0001", "serial_number": "x"},
            "profile": {"name": "Kids", "url": "/2.2/networks/network-0001/profiles/profile-0001", "paused": true}
        }));
        assert_eq!(
            summary["interface"],
            json!({"frequency": "5", "frequency_unit": "GHz"})
        );
        assert_eq!(
            summary["source"],
            json!({"location": "Kitchen", "url": "/2.2/eeros/eero-0001"})
        );
        assert_eq!(
            summary["profile"],
            json!({"name": "Kids", "url": "/2.2/networks/network-0001/profiles/profile-0001"})
        );
    }

    #[test]
    fn reduced_objects_with_nothing_to_keep_are_omitted_and_non_objects_pass_through() {
        let summary = device_summary(&json!({
            "interface": {"tx_rate": 1},
            "source": "/2.2/eeros/eero-0001",
            "profile": null
        }));
        assert!(summary.get("interface").is_none());
        assert_eq!(summary["source"], "/2.2/eeros/eero-0001");
        assert_eq!(summary["profile"], Value::Null);
    }

    #[test]
    fn blocked_and_blacklisted_are_independent_keys() {
        let summary = device_summary(&json!({"blocked": true, "blacklisted": false}));
        assert_eq!(summary["blocked"], true);
        assert_eq!(summary["blacklisted"], false);
        assert!(
            device_summary(&json!({"blocked": true}))
                .get("blacklisted")
                .is_none()
        );
    }

    #[test]
    fn every_documented_key_is_emitted_when_present() {
        let device = json!({
            "id": "i", "url": "u", "mac": "m", "nickname": "n", "hostname": "h",
            "display_name": "d", "manufacturer": "mf", "device_type": "t", "model_name": "mn",
            "ip": "1", "ips": ["1"], "connected": true, "wireless": true,
            "connection_type": "wireless",
            "interface": {"frequency": "2.4", "frequency_unit": "GHz"},
            "source": {"location": "l", "url": "su"}, "profile": {"name": "pn", "url": "pu"},
            "blocked": false, "blacklisted": false, "paused": false, "prioritized": true,
            "is_guest": false, "last_active": "la", "first_active": "fa"
        });
        let summary = device_summary(&device);
        assert_eq!(
            summary, device,
            "a device with only documented keys is unchanged"
        );
    }

    #[test]
    fn a_non_object_device_is_returned_as_is() {
        assert_eq!(device_summary(&json!("odd")), json!("odd"));
    }

    #[test]
    fn summarize_devices_handles_arrays_and_wrapped_lists() {
        let devices = json!([{"url": "/x/a"}, {"url": "/x/b"}]);
        let summaries = summarize_devices(&devices).expect("list");
        assert_eq!(summaries.len(), 2);
        assert_eq!(summaries[1]["id"], "b");
        assert!(summarize_devices(&json!({"devices": [{"url": "/x/a"}]})).is_some());
        assert!(summarize_devices(&json!({"data": [{"url": "/x/a"}]})).is_some());
        assert_eq!(summarize_devices(&json!([])).expect("empty list").len(), 0);
    }

    #[test]
    fn an_empty_wrapped_device_list_is_an_empty_list_not_an_unrecognised_shape() {
        for data in [
            json!({"devices": []}),
            json!({"data": []}),
            json!({"devices": [], "data": []}),
        ] {
            let summaries = summarize_devices(&data).expect("an empty list is still a list");
            assert!(summaries.is_empty(), "{data}");
        }
    }

    #[test]
    fn the_network_list_still_prefers_a_non_empty_array() {
        assert_eq!(
            unwrap_network_list(&json!({"networks": [], "data": [{"url": "/x/a"}]})).len(),
            1
        );
        assert!(unwrap_network_list(&json!({"networks": [], "data": []})).is_empty());
        assert!(unwrap_network_list(&json!({"devices": [{"url": "/x/a"}]})).is_empty());
    }

    #[test]
    fn the_output_is_read_through_getters_only() {
        let out = ToolOutput::from_envelope(&envelope(
            json!({"meta": {"server_time": "2026-01-01T00:00:10Z"}, "data": {"password": "x"}}),
        ))
        .with_network("network-0001")
        .with_detail(DetailMode::Summary, 3);
        assert_eq!(out.data()["password"], "[REDACTED]");
        assert_eq!(out.network_id(), Some("network-0001"));
        assert!(out.server_time().is_some());
        assert_eq!(out.detail(), Some(DetailMode::Summary));
        assert_eq!(out.count(), Some(3));
        assert!(out.window().is_none());
    }

    #[test]
    fn summarize_devices_reports_an_unrecognised_shape() {
        for data in [json!(null), json!({}), json!("x"), json!({"devices": "x"})] {
            assert!(summarize_devices(&data).is_none(), "{data}");
        }
    }
}
