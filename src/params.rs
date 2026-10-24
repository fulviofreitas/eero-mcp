//! Shared tool inputs: id fields, `refresh`, `detail`, the enumerations, integer ranges and the
//! schema helpers.
//!
//! # Portable schemas
//!
//! Every input schema must be portable: the root is an object, `additionalProperties` is false
//! (`#[serde(deny_unknown_fields)]`), no JSON-schema type arrays, no `default` keyword, every
//! property described. An optional field is therefore always written with this exact recipe, which
//! is a single type, left out of `required`, with the `default` that serde's default attribute
//! would add stripped:
//!
//! ```ignore
//! /// Description with the accepted forms and the default.
//! #[serde(default)]
//! #[schemars(with = "T", transform = drop_default)]
//! pub field: Option<T>,
//! ```
//!
//! where `T` is the field's inner type (`bool`, `String`, [`IdInput`], [`Cadence`], ...). For the
//! integer ranges use [`range_1_100`] or [`positive`] as the transform instead (with
//! `with = "i64"`). `tests/schema.rs` fails for any field that breaks the rules.
//!
//! # Id fields
//!
//! Every id field is `Option<IdInput>` (or `IdInput` when required): it accepts a JSON string or
//! an integer (LLM clients and the MCP Inspector send numeric-looking ids as numbers) and is
//! published as `type: string`. Validate it with [`crate::ids::Ids`] before any request.
//!
//! # Standard descriptions
//!
//! Use these words so the catalogue reads uniformly:
//!
//! - `network_id`: "Network to query. Accepts a bare network id, an API path such as
//!   /2.2/networks/ID, or an absolute URL on the eero API origin, as a string or an integer. Omit
//!   it to use the account's only network; with several networks the call fails and lists their
//!   ids (call `list_networks`)."
//! - `refresh`: "Set true to bypass the 60-second cache and fetch fresh data (the fresh response
//!   is cached again). Defaults to false."
//! - `start`: "Start of the window as an RFC 3339 timestamp, for example 2026-10-16T00:00:00Z.
//!   Defaults to 7 days before end (24 hours for `get_channel_utilization`); with both omitted the
//!   window ends now."
//! - `end`: the same, "End of the window ... Defaults to 7 days after start, or now when start is
//!   omitted too."
//! - `cadence`: "Bucket size: daily or hourly. Defaults to daily."
//! - `timezone`: "IANA time zone name, such as `America/Los_Angeles`, passed to eero unchanged."
//! - `insight_type`: "Insight category. Defaults to blocked."

use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::errors::ToolError;

/// A schemars field transform: strips the `default` keyword that serde's default attribute makes
/// schemars add. Defaults are stated in the field description instead.
pub fn drop_default(schema: &mut Schema) {
    schema.remove("default");
}

/// A schemars field transform for an integer from 1 to 100 (`limit`, `page_size`): single
/// `integer` type with `minimum` and `maximum`, no `default`, no `format`.
pub fn range_1_100(schema: &mut Schema) {
    integer_range(schema, 1, Some(100));
}

/// A schemars field transform for a positive integer up to [`u32::MAX`] (`granularity`,
/// `busy_threshold`): the bound [`positive_integer`] enforces, published so the schema and the
/// runtime check agree.
pub fn positive(schema: &mut Schema) {
    integer_range(schema, 1, Some(i64::from(u32::MAX)));
}

/// A schemars field transform for a count (zero or more): single `integer` type with a `minimum`
/// of 0, and without the non-standard `uint64` format schemars adds for unsigned integers.
pub fn non_negative(schema: &mut Schema) {
    integer_range(schema, 0, None);
}

fn integer_range(schema: &mut Schema, minimum: i64, maximum: Option<i64>) {
    drop_default(schema);
    schema.remove("format");
    schema.insert("type".to_owned(), "integer".into());
    schema.insert("minimum".to_owned(), minimum.into());
    if let Some(maximum) = maximum {
        schema.insert("maximum".to_owned(), maximum.into());
    }
}

/// Joins the lines of a wrapped description into running text; blank lines still separate
/// paragraphs. Doc comments are wrapped in the source, and schemars keeps their line breaks.
pub fn collapse_whitespace(text: &str) -> String {
    text.split("\n\n")
        .map(|paragraph| paragraph.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|paragraph| !paragraph.is_empty())
        .collect::<Vec<_>>()
        .join("\n\n")
}

/// Collapses the line breaks of every `description` in a JSON schema (recursively through
/// properties, definitions and sub-schemas). Values of `enum`, `const`, `default` and `examples`
/// are data, not schemas, and are left alone.
pub fn tidy_descriptions(schema: &mut serde_json::Value) {
    use serde_json::Value;

    match schema {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                match (key.as_str(), &*value) {
                    ("description", Value::String(text)) => {
                        *value = Value::String(collapse_whitespace(text));
                    }
                    ("enum" | "const" | "default" | "examples", _) => {}
                    _ => tidy_descriptions(value),
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(tidy_descriptions),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// An id supplied as a JSON string or integer, held as text. Published as `type: string`.
///
/// Surrounding whitespace is kept here; [`crate::ids`] trims and validates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdInput(String);

impl IdInput {
    /// Wraps text as an id input.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The text as supplied (an integer is already rendered in decimal).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

struct IdVisitor;

impl Visitor<'_> for IdVisitor {
    type Value = IdInput;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string or an integer id")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<IdInput, E> {
        Ok(IdInput(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<IdInput, E> {
        Ok(IdInput(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<IdInput, E> {
        Ok(IdInput(value.to_string()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<IdInput, E> {
        Ok(IdInput(value.to_string()))
    }
}

impl<'de> Deserialize<'de> for IdInput {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(IdVisitor)
    }
}

impl JsonSchema for IdInput {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("IdInput")
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "string" })
    }
}

/// Defines an enumeration input: string values, `Serialize` for the output echo, an inline
/// single-type schema, `as_str`, and `ALL` for tests. `default = Variant` adds `Default`; an
/// enumeration with no default (a filter that is simply absent, such as `Band`) gets none, so
/// `unwrap_or_default()` can never invent a value. Variants carry no doc comments on purpose:
/// schemars would turn them into a `oneOf` of constants instead of a plain `enum`.
macro_rules! string_enum {
    (
        $(#[$meta:meta])*
        $name:ident {
            $( $variant:ident => $text:literal ),+ $(,)?
        }
        $( default = $default:ident )?
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        #[schemars(inline)]
        #[allow(missing_docs)]
        pub enum $name {
            $( #[serde(rename = $text)] $variant ),+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant ),+ ];

            /// The wire string.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $text ),+
                }
            }
        }

        $(
            impl Default for $name {
                fn default() -> Self {
                    Self::$default
                }
            }
        )?
    };
}

string_enum! {
    /// How much of each device `list_devices` returns.
    DetailMode {
        Summary => "summary",
        Full => "full",
    }
    default = Summary
}

string_enum! {
    /// Bucket size of the usage and insight reads; exactly the values rusteero accepts.
    Cadence {
        Daily => "daily",
        Hourly => "hourly",
    }
    default = Daily
}

string_enum! {
    /// The insight category of tools 38 to 40, from the observed eero API spec.
    InsightType {
        Inspected => "inspected",
        Blocked => "blocked",
        Malware => "malware",
        Phishing => "phishing",
        Botnet => "botnet",
        Filtered => "filtered",
        Adult => "adult",
        Illegal => "illegal",
        Violent => "violent",
        Adblock => "adblock",
        Datausage => "datausage",
    }
    default = Blocked
}

string_enum! {
    /// The radio band filter of `get_channel_utilization`; rusteero's band list.
    Band {
        Band24GHz => "band_2_4GHz",
        Band5GHzLow => "band_5GHz_low",
        Band5GHzHigh => "band_5GHz_high",
        Band5GHzFull => "band_5GHz_full",
        Band6GHz => "band_6GHz",
    }
}

/// Checks an optional integer against `min..=max` and narrows it to `u32`.
///
/// The error names `field` and never echoes the value.
pub fn bounded(
    field: &'static str,
    value: Option<i64>,
    min: u32,
    max: u32,
) -> Result<Option<u32>, ToolError> {
    let Some(value) = value else {
        return Ok(None);
    };
    u32::try_from(value)
        .ok()
        .filter(|checked| (min..=max).contains(checked))
        .map(Some)
        .ok_or_else(|| {
            ToolError::invalid_argument(field, format!("must be an integer from {min} to {max}"))
        })
}

/// `limit`: 1 to 100.
pub fn limit(value: Option<i64>) -> Result<Option<u32>, ToolError> {
    bounded("limit", value, 1, 100)
}

/// `page_size`: 1 to 100.
pub fn page_size(value: Option<i64>) -> Result<Option<u32>, ToolError> {
    bounded("page_size", value, 1, 100)
}

/// A positive integer (`granularity`, `busy_threshold`): 1 to [`u32::MAX`]; zero, negatives and
/// larger values are rejected.
pub fn positive_integer(field: &'static str, value: Option<i64>) -> Result<Option<u32>, ToolError> {
    bounded(field, value, 1, u32::MAX)
}

/// Input of tools that take only `refresh` (`get_account`, `list_networks`).
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RefreshParams {
    /// Set true to bypass the 60-second cache and fetch fresh data (the fresh response is cached
    /// again). Defaults to false.
    #[serde(default)]
    #[schemars(with = "bool", transform = drop_default)]
    pub refresh: Option<bool>,
}

/// Input of tools that take only `network_id`.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkParams {
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
}

/// Input of cached tools that take `network_id` and `refresh`.
// The field docs are published as schema descriptions for agents: no markdown backticks there.
#[allow(clippy::doc_markdown)]
#[derive(Debug, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NetworkRefreshParams {
    /// Network to query. Accepts a bare network id, an API path such as /2.2/networks/ID, or an
    /// absolute URL on the eero API origin, as a string or an integer. Omit it to use the
    /// account's only network; with several networks the call fails and lists their ids (call
    /// list_networks).
    #[serde(default)]
    #[schemars(with = "IdInput", transform = drop_default)]
    pub network_id: Option<IdInput>,
    /// Set true to bypass the 60-second cache and fetch fresh data (the fresh response is cached
    /// again). Defaults to false.
    #[serde(default)]
    #[schemars(with = "bool", transform = drop_default)]
    pub refresh: Option<bool>,
}

#[cfg(test)]
mod tests {
    use rmcp::handler::server::common::schema_for_input;
    use serde_json::{Value, json};

    use super::*;

    #[allow(dead_code)] // only its schema is inspected
    #[derive(Debug, Deserialize, JsonSchema)]
    #[serde(deny_unknown_fields)]
    struct Probe {
        /// Required id.
        id: IdInput,
        /// Optional id.
        #[serde(default)]
        #[schemars(with = "IdInput", transform = drop_default)]
        other: Option<IdInput>,
        /// Page size.
        #[serde(default)]
        #[schemars(with = "i64", transform = range_1_100)]
        page: Option<i64>,
        /// Granularity.
        #[serde(default)]
        #[schemars(with = "i64", transform = positive)]
        granularity: Option<i64>,
        /// Cadence.
        #[serde(default)]
        #[schemars(with = "Cadence", transform = drop_default)]
        cadence: Option<Cadence>,
        /// Band.
        #[serde(default)]
        #[schemars(with = "Band", transform = drop_default)]
        band: Option<Band>,
        /// Insight.
        #[serde(default)]
        #[schemars(with = "InsightType", transform = drop_default)]
        insight: Option<InsightType>,
        /// Detail.
        #[serde(default)]
        #[schemars(with = "DetailMode", transform = drop_default)]
        detail: Option<DetailMode>,
    }

    fn probe_schema() -> Value {
        Value::Object((*schema_for_input::<Probe>().expect("object schema")).clone())
    }

    #[test]
    fn ids_accept_strings_and_integers() {
        let from = |value: Value| serde_json::from_value::<IdInput>(value);
        assert_eq!(
            from(json!("network-0001")).expect("string").as_str(),
            "network-0001"
        );
        assert_eq!(from(json!(12345)).expect("integer").as_str(), "12345");
        assert_eq!(from(json!(0)).expect("zero").as_str(), "0");
        assert_eq!(from(json!(-7)).expect("negative").as_str(), "-7");
        assert_eq!(
            from(json!(u64::MAX)).expect("large").as_str(),
            u64::MAX.to_string()
        );
        assert_eq!(
            from(json!("  padded  ")).expect("padding kept").as_str(),
            "  padded  "
        );
    }

    #[test]
    fn ids_reject_floats_bools_arrays_objects_and_null() {
        for bad in [
            json!(1.5),
            json!(true),
            json!([1]),
            json!({"a": 1}),
            json!(null),
        ] {
            assert!(
                serde_json::from_value::<IdInput>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn optional_ids_accept_null_as_absent() {
        let params: NetworkParams =
            serde_json::from_value(json!({"network_id": null})).expect("null is absent");
        assert!(params.network_id.is_none());
        let params: NetworkParams = serde_json::from_value(json!({})).expect("empty");
        assert!(params.network_id.is_none());
        let params: NetworkParams =
            serde_json::from_value(json!({"network_id": 1})).expect("integer id");
        assert_eq!(params.network_id.expect("id").as_str(), "1");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(serde_json::from_value::<NetworkParams>(json!({"bogus": 1})).is_err());
        assert!(serde_json::from_value::<RefreshParams>(json!({"network_id": "n"})).is_err());
        assert!(serde_json::from_value::<NetworkRefreshParams>(json!({"detail": "full"})).is_err());
    }

    #[test]
    fn schema_is_portable() {
        let schema = probe_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        let text = schema.to_string();
        assert!(!text.contains("\"default\""), "no default keyword: {text}");
        assert!(!text.contains("\"null\""), "no null types: {text}");
        assert!(
            !text.contains("$ref"),
            "enumerations and ids are inlined: {text}"
        );
        let properties = schema["properties"].as_object().expect("properties");
        for (name, property) in properties {
            assert!(
                property["type"].is_string(),
                "{name} has a single string type: {property}"
            );
            assert!(property["description"].is_string(), "{name} is described");
        }
        assert_eq!(schema["required"], json!(["id"]));
    }

    #[test]
    fn id_fields_are_published_as_strings() {
        let schema = probe_schema();
        assert_eq!(schema["properties"]["id"]["type"], "string");
        assert_eq!(schema["properties"]["other"]["type"], "string");
    }

    #[test]
    fn integer_ranges_are_published_as_minimum_and_maximum() {
        let schema = probe_schema();
        let page = &schema["properties"]["page"];
        assert_eq!(page["type"], "integer");
        assert_eq!(page["minimum"], 1);
        assert_eq!(page["maximum"], 100);
        assert!(page.get("format").is_none());
        let granularity = &schema["properties"]["granularity"];
        assert_eq!(granularity["type"], "integer");
        assert_eq!(granularity["minimum"], 1);
        assert_eq!(granularity["maximum"], 4_294_967_295_u32);
    }

    #[test]
    fn enumerations_are_published_as_string_enums() {
        let schema = probe_schema();
        let values = |name: &str| -> Vec<String> {
            schema["properties"][name]["enum"]
                .as_array()
                .unwrap_or_else(|| panic!("{name} has an enum: {schema}"))
                .iter()
                .map(|v| v.as_str().expect("string").to_owned())
                .collect()
        };
        assert_eq!(values("cadence"), ["daily", "hourly"]);
        assert_eq!(values("detail"), ["summary", "full"]);
        assert_eq!(
            values("band"),
            [
                "band_2_4GHz",
                "band_5GHz_low",
                "band_5GHz_high",
                "band_5GHz_full",
                "band_6GHz"
            ]
        );
        assert_eq!(
            values("insight"),
            [
                "inspected",
                "blocked",
                "malware",
                "phishing",
                "botnet",
                "filtered",
                "adult",
                "illegal",
                "violent",
                "adblock",
                "datausage"
            ]
        );
        for name in ["cadence", "detail", "band", "insight"] {
            assert_eq!(schema["properties"][name]["type"], "string", "{name}");
        }
    }

    #[test]
    fn shared_param_structs_have_portable_schemas() {
        for schema in [
            schema_for_input::<RefreshParams>().expect("schema"),
            schema_for_input::<NetworkParams>().expect("schema"),
            schema_for_input::<NetworkRefreshParams>().expect("schema"),
        ] {
            let value = Value::Object((*schema).clone());
            let text = value.to_string();
            assert_eq!(value["additionalProperties"], false);
            assert!(!text.contains("\"default\""), "{text}");
            assert!(!text.contains("\"null\""), "{text}");
            assert!(
                value.get("required").is_none(),
                "everything optional: {text}"
            );
            for (name, property) in value["properties"].as_object().expect("properties") {
                assert!(property["description"].is_string(), "{name}");
                assert!(property["type"].is_string(), "{name}");
            }
        }
        let refresh =
            Value::Object((*schema_for_input::<RefreshParams>().expect("schema")).clone());
        assert_eq!(refresh["properties"]["refresh"]["type"], "boolean");
    }

    #[test]
    fn enumerations_match_rusteeros_lists() {
        let cadence: Vec<_> = Cadence::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(cadence, rusteero::params::CADENCE_VALUES);
        let bands: Vec<_> = Band::ALL.iter().map(|b| b.as_str()).collect();
        assert_eq!(
            bands,
            rusteero::endpoints::events::CHANNEL_UTILIZATION_BANDS
        );
    }

    #[test]
    fn as_str_matches_serde_for_every_value() {
        fn check<T: Serialize + Copy>(all: &[T], as_str: impl Fn(T) -> &'static str) {
            for value in all {
                assert_eq!(
                    serde_json::to_value(value).expect("serialize"),
                    as_str(*value)
                );
            }
        }
        check(DetailMode::ALL, DetailMode::as_str);
        check(Cadence::ALL, Cadence::as_str);
        check(InsightType::ALL, InsightType::as_str);
        check(Band::ALL, Band::as_str);
    }

    #[test]
    fn enumerations_deserialize_only_their_values() {
        assert_eq!(
            serde_json::from_value::<Cadence>(json!("hourly")).expect("value"),
            Cadence::Hourly
        );
        for bad in ["Hourly", "weekly", "", "DAILY"] {
            assert!(
                serde_json::from_value::<Cadence>(json!(bad)).is_err(),
                "{bad}"
            );
        }
        assert!(serde_json::from_value::<Band>(json!("band_5GHz")).is_err());
        assert!(serde_json::from_value::<InsightType>(json!("everything")).is_err());
        assert!(serde_json::from_value::<DetailMode>(json!("brief")).is_err());
    }

    #[test]
    fn defaults_are_the_documented_ones() {
        assert_eq!(DetailMode::default(), DetailMode::Summary);
        assert_eq!(Cadence::default(), Cadence::Daily);
        assert_eq!(InsightType::default(), InsightType::Blocked);
    }

    #[test]
    fn limit_and_page_size_accept_1_to_100() {
        assert_eq!(limit(None).expect("none"), None);
        assert_eq!(limit(Some(1)).expect("min"), Some(1));
        assert_eq!(limit(Some(100)).expect("max"), Some(100));
        assert_eq!(page_size(Some(50)).expect("mid"), Some(50));
        for bad in [0, -1, 101, i64::MAX, i64::MIN, 4_294_967_297] {
            let error = limit(Some(bad)).expect_err("out of range");
            assert_eq!(error.field.as_deref(), Some("limit"), "{bad}");
            assert_eq!(error.code.as_str(), "invalid_argument");
            let error = page_size(Some(bad)).expect_err("out of range");
            assert_eq!(error.field.as_deref(), Some("page_size"), "{bad}");
        }
    }

    #[test]
    fn positive_integers_reject_zero_and_negatives() {
        assert_eq!(positive_integer("granularity", None).expect("none"), None);
        assert_eq!(
            positive_integer("granularity", Some(1)).expect("one"),
            Some(1)
        );
        assert_eq!(
            positive_integer("busy_threshold", Some(4_294_967_295)).expect("u32 max"),
            Some(u32::MAX)
        );
        for bad in [0, -5, 4_294_967_296] {
            let error = positive_integer("busy_threshold", Some(bad)).expect_err("invalid");
            assert_eq!(error.field.as_deref(), Some("busy_threshold"));
            assert_eq!(error.message, "must be an integer from 1 to 4294967295");
            assert!(
                !error.message.contains(&bad.to_string()),
                "never echoes the value"
            );
        }
    }

    #[test]
    fn wrapped_descriptions_are_joined_and_paragraphs_kept() {
        assert_eq!(
            collapse_whitespace("one\ntwo  three\n  four"),
            "one two three four"
        );
        assert_eq!(collapse_whitespace("a\nb\n\nc\nd"), "a b\n\nc d");
        assert_eq!(collapse_whitespace("  padded  "), "padded");
        assert_eq!(collapse_whitespace(""), "");
    }

    #[test]
    fn tidy_descriptions_touches_only_descriptions() {
        let mut schema = json!({
            "description": "top\nlevel",
            "properties": {
                "description": {"description": "a\nb", "enum": ["x\ny"], "default": "p\nq"},
                "other": {"type": "string", "description": "c\n d"}
            },
            "examples": ["keep\nme"]
        });
        tidy_descriptions(&mut schema);
        assert_eq!(schema["description"], "top level");
        assert_eq!(schema["properties"]["description"]["description"], "a b");
        assert_eq!(schema["properties"]["description"]["enum"], json!(["x\ny"]));
        assert_eq!(schema["properties"]["description"]["default"], "p\nq");
        assert_eq!(schema["properties"]["other"]["description"], "c d");
        assert_eq!(schema["examples"], json!(["keep\nme"]));
    }
}
