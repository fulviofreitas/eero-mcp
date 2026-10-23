//! Time-window defaults and validation.
//!
//! Used by `get_channel_utilization` (default span 24 hours) and the usage and insight tools
//! (default span 7 days), and, through [`check_timestamp`], by every tool that passes an RFC 3339
//! timestamp through unchanged (`list_speed_tests` start and end, the `before` cursors).
//!
//! - Both bounds omitted: the window is the default span ending now, in UTC with whole seconds.
//! - One bound given: the other is derived from it with the same span.
//! - Caller-supplied bounds are forwarded unchanged after validation; derived bounds are rendered
//!   in UTC.
//! - `start` must be strictly before `end`.
//!
//! Every function is pure over an injected `now`, so the defaults are testable.

use jiff::{SignedDuration, Timestamp};

use crate::errors::ToolError;

/// The default span of a window when a bound is omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Span {
    /// Seven days: the usage and insight tools.
    Days7,
    /// Twenty-four hours: `get_channel_utilization`.
    Hours24,
}

impl Span {
    /// The span as a duration.
    pub const fn duration(self) -> SignedDuration {
        match self {
            Self::Days7 => SignedDuration::from_hours(7 * 24),
            Self::Hours24 => SignedDuration::from_hours(24),
        }
    }
}

/// An effective window: RFC 3339 `start` and `end`, ready to forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    /// The inclusive start, as the caller wrote it or rendered in UTC when derived.
    pub start: String,
    /// The end, as the caller wrote it or rendered in UTC when derived.
    pub end: String,
}

/// Whether `value` has the shape of an RFC 3339 `date-time`: `YYYY-MM-DDTHH:MM:SS`, an optional
/// `.` and one or more fraction digits, then `Z` or `+HH:MM` / `-HH:MM`. The `T` and `Z` are
/// accepted in either case, as the grammar allows; a space separator is not (it is a readability
/// allowance outside the grammar).
///
/// jiff's own parser also accepts wider ISO 8601 spellings (no seconds, basic format, `+0000`
/// offsets, expanded years, a comma fraction, offsets with seconds). Caller bounds are forwarded to
/// eero unchanged, so none of those may pass; jiff is only used for calendar validity.
fn is_rfc3339_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .is_some_and(|part| part.iter().all(u8::is_ascii_digit))
    };
    let one_of =
        |index: usize, allowed: &[u8]| bytes.get(index).is_some_and(|byte| allowed.contains(byte));
    let date_time = digits(0..4)
        && one_of(4, b"-")
        && digits(5..7)
        && one_of(7, b"-")
        && digits(8..10)
        && one_of(10, b"Tt")
        && digits(11..13)
        && one_of(13, b":")
        && digits(14..16)
        && one_of(16, b":")
        && digits(17..19);
    if !date_time {
        return false;
    }
    let mut rest = &bytes[19..];
    if let [b'.', fraction @ ..] = rest {
        let length = fraction
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if length == 0 {
            return false;
        }
        rest = &fraction[length..];
    }
    match rest {
        [b'Z' | b'z'] => true,
        [b'+' | b'-', h1, h2, b':', m1, m2] => {
            [h1, h2, m1, m2].iter().all(|byte| byte.is_ascii_digit())
        }
        _ => false,
    }
}

/// Parses an RFC 3339 timestamp for the named tool parameter.
///
/// The shape is checked strictly first (`is_rfc3339_shape`); jiff then rejects impossible
/// calendar values (month 13, hour 25, an out-of-range offset).
pub fn parse_timestamp(field: &'static str, value: &str) -> Result<Timestamp, ToolError> {
    let invalid = || {
        ToolError::invalid_argument(
            field,
            "must be an RFC 3339 timestamp, for example 2026-10-16T00:00:00Z",
        )
    };
    if !is_rfc3339_shape(value) {
        return Err(invalid());
    }
    value.parse::<Timestamp>().map_err(|_| invalid())
}

/// Validates a timestamp that is passed through unchanged (`before`, speed-test `start`/`end`).
pub fn check_timestamp(field: &'static str, value: &str) -> Result<(), ToolError> {
    parse_timestamp(field, value).map(drop)
}

/// Renders a timestamp in UTC with whole seconds, such as `2026-10-16T00:00:00Z`.
fn render(timestamp: Timestamp) -> String {
    Timestamp::from_second(timestamp.as_second())
        .unwrap_or(timestamp)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Resolves the effective window at `now`.
pub fn resolve_at(
    start: Option<&str>,
    end: Option<&str>,
    span: Span,
    now: Timestamp,
) -> Result<Window, ToolError> {
    let duration = span.duration();
    let out_of_range = |field| ToolError::invalid_argument(field, "is outside the supported range");
    match (start, end) {
        (Some(start), Some(end)) => {
            let from = parse_timestamp("start", start)?;
            let to = parse_timestamp("end", end)?;
            if from >= to {
                return Err(ToolError::invalid_argument(
                    "start",
                    "start must be strictly before end",
                ));
            }
            Ok(Window {
                start: start.to_owned(),
                end: end.to_owned(),
            })
        }
        (Some(start), None) => {
            let from = parse_timestamp("start", start)?;
            let to = from
                .checked_add(duration)
                .map_err(|_| out_of_range("start"))?;
            Ok(Window {
                start: start.to_owned(),
                end: render(to),
            })
        }
        (None, Some(end)) => {
            let to = parse_timestamp("end", end)?;
            let from = to.checked_sub(duration).map_err(|_| out_of_range("end"))?;
            Ok(Window {
                start: render(from),
                end: end.to_owned(),
            })
        }
        (None, None) => {
            let to = Timestamp::from_second(now.as_second()).map_err(|_| out_of_range("end"))?;
            let from = to
                .checked_sub(duration)
                .map_err(|_| out_of_range("start"))?;
            Ok(Window {
                start: render(from),
                end: render(to),
            })
        }
    }
}

/// Resolves the effective window, ending now when a bound is omitted.
pub fn resolve(start: Option<&str>, end: Option<&str>, span: Span) -> Result<Window, ToolError> {
    resolve_at(start, end, span, Timestamp::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        "2026-10-23T12:34:56.789Z".parse().expect("timestamp")
    }

    fn window(start: Option<&str>, end: Option<&str>, span: Span) -> Result<Window, ToolError> {
        resolve_at(start, end, span, now())
    }

    #[test]
    fn both_omitted_defaults_to_seven_days_ending_now_in_whole_seconds() {
        let w = window(None, None, Span::Days7).expect("window");
        assert_eq!(w.end, "2026-10-23T12:34:56Z");
        assert_eq!(w.start, "2026-10-16T12:34:56Z");
    }

    #[test]
    fn both_omitted_defaults_to_24_hours_for_channel_utilization() {
        let w = window(None, None, Span::Hours24).expect("window");
        assert_eq!(w.end, "2026-10-23T12:34:56Z");
        assert_eq!(w.start, "2026-10-22T12:34:56Z");
    }

    #[test]
    fn only_start_derives_end_with_the_same_span() {
        let w = window(Some("2026-10-01T00:00:00Z"), None, Span::Days7).expect("window");
        assert_eq!(
            w.start, "2026-10-01T00:00:00Z",
            "caller bound forwarded unchanged"
        );
        assert_eq!(w.end, "2026-10-08T00:00:00Z");
        let w = window(Some("2026-10-01T00:00:00Z"), None, Span::Hours24).expect("window");
        assert_eq!(w.end, "2026-10-02T00:00:00Z");
    }

    #[test]
    fn only_end_derives_start_with_the_same_span() {
        let w = window(None, Some("2026-10-08T00:00:00Z"), Span::Days7).expect("window");
        assert_eq!(w.start, "2026-10-01T00:00:00Z");
        assert_eq!(
            w.end, "2026-10-08T00:00:00Z",
            "caller bound forwarded unchanged"
        );
    }

    #[test]
    fn derived_bounds_are_rendered_in_utc_from_an_offset_input() {
        let w = window(Some("2026-10-01T02:00:00+02:00"), None, Span::Days7).expect("window");
        assert_eq!(w.start, "2026-10-01T02:00:00+02:00", "forwarded as written");
        assert_eq!(w.end, "2026-10-08T00:00:00Z", "derived in UTC");
        let w = window(None, Some("2026-10-08T05:30:00+05:30"), Span::Days7).expect("window");
        assert_eq!(w.start, "2026-10-01T00:00:00Z");
    }

    #[test]
    fn both_given_are_forwarded_unchanged() {
        let w = window(
            Some("2026-10-16T00:00:00Z"),
            Some("2026-10-23T00:00:00+00:00"),
            Span::Days7,
        )
        .expect("window");
        assert_eq!(w.start, "2026-10-16T00:00:00Z");
        assert_eq!(w.end, "2026-10-23T00:00:00+00:00");
    }

    #[test]
    fn start_must_be_strictly_before_end() {
        for (start, end) in [
            ("2026-10-23T00:00:00Z", "2026-10-23T00:00:00Z"),
            ("2026-10-24T00:00:00Z", "2026-10-23T00:00:00Z"),
            // The same instant in different offsets is equal, not ordered.
            ("2026-10-23T02:00:00+02:00", "2026-10-23T00:00:00Z"),
        ] {
            let error = window(Some(start), Some(end), Span::Days7).expect_err("must fail");
            assert_eq!(error.field.as_deref(), Some("start"));
            assert_eq!(error.code.as_str(), "invalid_argument");
        }
    }

    #[test]
    fn ordering_compares_instants_not_text() {
        // Later local time but earlier instant.
        assert!(
            window(
                Some("2026-10-23T01:00:00+05:00"),
                Some("2026-10-23T00:00:00+00:00"),
                Span::Days7
            )
            .is_ok()
        );
    }

    #[test]
    fn malformed_timestamps_name_the_offending_parameter() {
        for bad in [
            "",
            "yesterday",
            "2026-10-16",
            "2026-10-16T00:00:00",
            "2026-13-16T00:00:00Z",
            "2026-10-16T25:00:00Z",
            "1760000000",
            "2026-10-16T00:00:00Z[America/New_York]",
            "2026-10-16T00:00:00Z ",
            // Spellings jiff accepts but RFC 3339 does not: they must never reach eero.
            "2026-10-16T00:00Z",
            "2026-10-16T00Z",
            "20261016T000000Z",
            "2026-10-16T00:00:00+0000",
            "2026-10-16T00:00:00+00",
            "+002026-10-16T00:00:00Z",
            "2026-10-16T00:00:00,5Z",
            "2026-10-16T00:00:00+05:30:15",
            "2026-10-16 00:00:00Z",
            "2026-10-16T00:00:00.Z",
            "2026-10-16T00:00:00 Z",
            "2026-10-16T00:00:00",
            "2026-10-16T00:00:00ZZ",
            "2026-10-16T00:00:00+99:00",
            "\u{ff12}\u{ff10}26-10-16T00:00:00Z",
        ] {
            let start = window(Some(bad), None, Span::Days7).expect_err(bad);
            assert_eq!(start.field.as_deref(), Some("start"), "{bad:?}");
            let end = window(None, Some(bad), Span::Days7).expect_err(bad);
            assert_eq!(end.field.as_deref(), Some("end"), "{bad:?}");
            let both = window(Some("2026-10-16T00:00:00Z"), Some(bad), Span::Days7).expect_err(bad);
            assert_eq!(both.field.as_deref(), Some("end"), "{bad:?}");
        }
    }

    #[test]
    fn validation_messages_never_echo_the_input() {
        let error = window(Some("do-not-echo-me"), None, Span::Days7).expect_err("invalid");
        assert!(!error.message.contains("do-not-echo-me"));
    }

    #[test]
    fn rfc_3339_variants_are_accepted() {
        for good in [
            "2026-10-16T00:00:00Z",
            "2026-10-16T00:00:00z",
            "2026-10-16t00:00:00Z",
            "2026-10-16T00:00:00.123Z",
            "2026-10-16T00:00:00.123456789Z",
            "2026-10-16T00:00:00+00:00",
            "2026-10-16T00:00:00-07:00",
            "2026-10-16T00:00:00.5+05:30",
        ] {
            assert!(check_timestamp("before", good).is_ok(), "{good}");
        }
    }

    #[test]
    fn check_timestamp_reports_the_given_field() {
        let error = check_timestamp("before", "nope").expect_err("invalid");
        assert_eq!(error.field.as_deref(), Some("before"));
        assert_eq!(
            check_timestamp("end", "nope")
                .expect_err("invalid")
                .field
                .as_deref(),
            Some("end")
        );
    }

    #[test]
    fn arithmetic_overflow_is_an_argument_error_not_a_panic() {
        let error = window(Some("9999-12-31T23:59:59Z"), None, Span::Days7).expect_err("overflow");
        assert_eq!(error.field.as_deref(), Some("start"));
        let error = window(None, Some("-009999-01-01T00:00:00Z"), Span::Days7);
        // Either the parser or the arithmetic rejects it; both are argument errors.
        assert!(error.is_err());
    }

    #[test]
    fn resolve_uses_the_real_clock_and_ends_on_a_whole_second() {
        let w = resolve(None, None, Span::Hours24).expect("window");
        assert!(w.end.ends_with('Z'));
        assert!(!w.end.contains('.'));
        let start: Timestamp = w.start.parse().expect("start parses");
        let end: Timestamp = w.end.parse().expect("end parses");
        assert_eq!(end.as_second() - start.as_second(), 24 * 3600);
    }
}
