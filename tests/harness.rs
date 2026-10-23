//! The test harness itself: the helpers every tool suite leans on must be strict, or a suite can
//! pass while the server sends something it should not.

mod common;

use common::ExactQuery;
use url::Url;
use wiremock::http::{HeaderMap, Method};
use wiremock::{Match, Request};

fn request(url: &str) -> Request {
    Request {
        url: Url::parse(url).expect("url"),
        method: Method::GET,
        headers: HeaderMap::new(),
        body: Vec::new(),
    }
}

#[test]
fn exact_query_matches_the_same_pairs_in_any_order() {
    let matcher = ExactQuery::new(&[("start", "2026-10-16T00:00:00Z"), ("cadence", "daily")]);
    assert!(matcher.matches(&request(
        "http://mock.test/x?start=2026-10-16T00%3A00%3A00Z&cadence=daily"
    )));
    assert!(matcher.matches(&request(
        "http://mock.test/x?cadence=daily&start=2026-10-16T00:00:00Z"
    )));
}

#[test]
fn exact_query_rejects_an_extra_a_missing_and_a_different_parameter() {
    let matcher = ExactQuery::new(&[("cadence", "daily")]);
    for url in [
        "http://mock.test/x?cadence=daily&timezone=UTC",
        "http://mock.test/x?cadence=daily&cadence=daily",
        "http://mock.test/x",
        "http://mock.test/x?cadence=hourly",
        "http://mock.test/x?Cadence=daily",
        "http://mock.test/x?other=daily",
    ] {
        assert!(!matcher.matches(&request(url)), "{url}");
    }
}

#[test]
fn an_empty_exact_query_means_no_query_string_at_all() {
    let matcher = ExactQuery::new(&[]);
    assert!(matcher.matches(&request("http://mock.test/x")));
    assert!(matcher.matches(&request("http://mock.test/x?")));
    assert!(!matcher.matches(&request("http://mock.test/x?refresh=true")));
    assert!(!matcher.matches(&request("http://mock.test/x?a=")));
}
