//! Exact-key secret redaction.
//!
//! Applied to every tool output, recursively through objects and arrays. A value is replaced by
//! the string `"[REDACTED]"` when its key, compared case-insensitively, exactly equals an entry of
//! [`DENY_LIST`] and the value is neither null nor empty (an empty string, array or object), so
//! "no password set" stays visible. A non-empty object or array under a listed key is replaced
//! whole.
//!
//! Matching is exact, unlike rusteero's substring-based redaction, which would also hide `mac`,
//! `ssid`, `serial`, `email` and `phone`: the data agents need. The set is closed; adding or
//! removing a key requires a test change.

use serde_json::Value;

/// The replacement for a redacted value.
pub const REDACTED: &str = "[REDACTED]";

/// The closed deny-list of secret-bearing keys, compared case-insensitively and exactly.
pub const DENY_LIST: [&str; 25] = [
    // Wi-Fi and guest credentials.
    "password",
    "passphrase",
    "psk",
    "pre_shared_key",
    "wpa_key",
    // Thread network credentials (network_key can also name a Wi-Fi key).
    "network_key",
    "pskc",
    "master_key",
    // Generic key material.
    "private_key",
    "secret",
    "client_secret",
    "api_key",
    // Session and credential records.
    "token",
    "user_token",
    "access_token",
    "refresh_token",
    "session_id",
    "session_token",
    // Further secret-bearing keys found in the observed eero OpenAPI spec.
    "auth_token",
    "temporary_token",
    "activation_token",
    "guardian_secret",
    "authentication_key",
    "commissioning_credential",
    "pppoe_credentials",
];

/// Whether `key` is on the deny-list (ASCII case-insensitive, exact).
pub fn is_secret_key(key: &str) -> bool {
    DENY_LIST
        .iter()
        .any(|secret| key.eq_ignore_ascii_case(secret))
}

/// A value that a secret key may leave visible: null or empty.
fn is_null_or_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
        Value::Bool(_) | Value::Number(_) => false,
    }
}

/// Redacts `value` in place.
pub fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_secret_key(key) && !is_null_or_empty(child) {
                    *child = Value::String(REDACTED.to_owned());
                } else {
                    redact(child);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

/// Returns a redacted copy of `value`.
pub fn redacted(value: &Value) -> Value {
    let mut copy = value.clone();
    redact(&mut copy);
    copy
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn the_deny_list_is_the_closed_set_of_25() {
        assert_eq!(DENY_LIST.len(), 25);
        let mut sorted = DENY_LIST.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 25, "no duplicates");
        for key in DENY_LIST {
            assert_eq!(key, key.to_ascii_lowercase(), "entries are lower case");
        }
    }

    #[test]
    fn every_key_is_redacted() {
        for key in DENY_LIST {
            let mut value = json!({ key: "s3cret", "keep": "visible" });
            redact(&mut value);
            assert_eq!(value[key], REDACTED, "{key}");
            assert_eq!(value["keep"], "visible");
        }
    }

    #[test]
    fn matching_is_case_insensitive() {
        for key in [
            "Password",
            "PASSWORD",
            "Pre_Shared_Key",
            "WPA_KEY",
            "Session_Id",
        ] {
            let mut value = json!({ key: "s3cret" });
            redact(&mut value);
            assert_eq!(value[key], REDACTED, "{key}");
        }
    }

    #[test]
    fn redaction_reaches_any_depth_through_objects_and_arrays() {
        let mut value = json!({
            "data": {
                "networks": [
                    {"name": "n1", "guest_network": {"password": "guestpass000"}},
                    {"name": "n2", "wifi": [{"deep": [{"psk": "abc"}]}]}
                ]
            }
        });
        redact(&mut value);
        assert_eq!(
            value["data"]["networks"][0]["guest_network"]["password"],
            REDACTED
        );
        assert_eq!(value["data"]["networks"][0]["name"], "n1");
        assert_eq!(
            value["data"]["networks"][1]["wifi"][0]["deep"][0]["psk"],
            REDACTED
        );
    }

    #[test]
    fn top_level_arrays_and_scalars_are_handled() {
        let mut array = json!([{"token": "t"}, {"token": "u"}]);
        redact(&mut array);
        assert_eq!(array, json!([{"token": REDACTED}, {"token": REDACTED}]));
        let mut scalar = json!("password");
        redact(&mut scalar);
        assert_eq!(
            scalar, "password",
            "a value equal to a key name is not a key"
        );
    }

    #[test]
    fn null_and_empty_values_stay_visible() {
        let mut value = json!({
            "password": null,
            "psk": "",
            "token": [],
            "secret": {},
            "passphrase": "x"
        });
        redact(&mut value);
        assert_eq!(value["password"], Value::Null);
        assert_eq!(value["psk"], "");
        assert_eq!(value["token"], json!([]));
        assert_eq!(value["secret"], json!({}));
        assert_eq!(value["passphrase"], REDACTED);
    }

    #[test]
    fn non_empty_containers_under_a_listed_key_are_replaced_whole() {
        let mut value = json!({
            "pppoe_credentials": {"username": "u", "password": "p"},
            "secret": ["a", "b"],
            "token": 12345,
            "api_key": true
        });
        redact(&mut value);
        assert_eq!(value["pppoe_credentials"], REDACTED);
        assert_eq!(value["secret"], REDACTED);
        assert_eq!(value["token"], REDACTED);
        assert_eq!(value["api_key"], REDACTED);
    }

    #[test]
    fn an_empty_listed_container_is_still_walked_without_effect() {
        let mut value = json!({"password": {}});
        redact(&mut value);
        assert_eq!(value, json!({"password": {}}));
    }

    #[test]
    fn near_misses_and_data_agents_need_are_untouched() {
        let original = json!({
            "mac": "aa:bb:cc:00:00:01",
            "ssid": "Example-Network",
            "serial": "TESTSERIAL0001",
            "email": "user@example.com",
            "phone": "+15550100",
            "password_set": true,
            "passwords": "x",
            "my_password": "x",
            "token_type": "bearer",
            "tokens": ["a"],
            "secrets": "x",
            "keyboard": "x",
            "key": "x",
            "pass": "x",
            "session": "x",
            "password ": "x",
            " password": "x"
        });
        assert_eq!(redacted(&original), original);
    }

    #[test]
    fn redacted_returns_a_copy_and_leaves_the_input_alone() {
        let original = json!({"password": "p"});
        let copy = redacted(&original);
        assert_eq!(original["password"], "p");
        assert_eq!(copy["password"], REDACTED);
    }

    #[test]
    fn is_secret_key_is_exact() {
        assert!(is_secret_key("TOKEN"));
        assert!(!is_secret_key("tokens"));
        assert!(!is_secret_key(""));
    }
}
