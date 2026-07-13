//! VECTOR 15: AUDIT HUNTS: SSRF guard gaps in `WebSource`.
//!
//! Finding (SSRF / proxy-bypass class)
//! -----------------------------------
//! `WebSource` (the `keyhog scan --web <url>` surface) gates every fetch through
//! `is_disallowed_web_host` (URL-string pre-filter) and, on the direct path,
//! `resolve_and_screen` (post-resolution IP check). Both delegate the IP
//! decision to `is_disallowed_ipv4` in
//! `crates/sources/src/web/ssrf.rs:47-54`, which only refuses:
//!
//!     is_loopback || is_private || is_link_local || is_multicast
//!     || is_broadcast || is_unspecified
//!
//! That set is INCOMPLETE relative to keyhog's own canonical SSRF classifier,
//! `keyhog_verifier::bogon::ip_addr_is_bogon` (used by the live verifier and
//! the OOB collector). The bogon crate's own module docs
//! (`crates/verifier/src/bogon.rs:50-54`) explicitly instruct:
//!
//!     "Consumers that need stricter rules ... should layer their additional
//!      checks on top of `ip_addr_is_bogon`, not fork it."
//!
//! `WebSource` forked it and dropped these non-public ranges that an SSRF guard
//! MUST refuse:
//!
//!   * 0.0.0.0/8         "this network" (RFC 1122), on Linux a connect() to
//!                       0.x.y.z routes to the LOCAL host, so this is a direct
//!                       loopback-equivalent SSRF target. `is_unspecified()`
//!                       only matches the single 0.0.0.0, NOT the whole /8.
//!   * 100.64.0.0/10     Carrier-Grade NAT (RFC 6598) (internal infra).
//!   * 192.0.0.0/24      IETF protocol assignments (RFC 6890).
//!   * 198.18.0.0/15     benchmark range (RFC 2544) (internal).
//!   * 240.0.0.0/4       reserved / Class E (RFC 1112).
//!
//! The verifier blocks every one of these (verified: `is_private_url` /
//! `is_private_ip_addr` return `true` for all of them). `WebSource` does not 
//! it falls through and ATTEMPTS the outbound connection. That is the exact
//! SSRF surface the verifier was hardened against, left open on the web-fetch
//! path.
//!
//! Observable, deterministic distinction (no network success required): a URL
//! the SSRF guard REFUSES yields `SourceError::Other("refusing to fetch ...")`
//! BEFORE any socket is opened. A URL the guard misses falls through to a real
//! `client.get(url).send()`, whose error is "failed to fetch ... error sending
//! request", proving a connection was attempted. The tests assert the SSRF
//! refusal is present and the connection-attempt error is absent.
//!
//! Evidence: `crates/sources/src/web/ssrf.rs:47-54` (`is_disallowed_ipv4`),
//! `crates/sources/src/web.rs:133,188` (the gate call sites),
//! `crates/sources/src/web/ssrf.rs:151` (`resolve_and_screen` uses the same
//! incomplete predicate), vs `crates/verifier/src/bogon.rs:93-125` (the
//! complete classifier that already exists in-tree).
//!
//! Expected fix: replace the hand-rolled `is_disallowed_ipv4` / `is_disallowed_ipv6`
//! body (or layer on top of it) with `keyhog_verifier::bogon::ip_addr_is_bogon`
//! so the web-fetch path refuses the same ranges as the verifier. After the
//! fix, every URL below is refused before a socket is opened and these tests
//! pass.
//!
//! The entire file drives `WebSource`, so it is gated on the `web` feature 
//! without this the CI source-feature set (no `web`) fails to compile the
//! `keyhog_sources::WebSource` import (E0432).
#![cfg(feature = "web")]

use keyhog_core::Source;
use keyhog_sources::WebSource;

/// Drive a single URL through the public `WebSource::chunks()` path and return
/// the rendered error string (or a marker if a chunk was unexpectedly produced).
fn fetch_error(url: &str) -> String {
    let source = WebSource::new(vec![url.to_string()]);
    let results: Vec<_> = source.chunks().collect();
    assert_eq!(
        results.len(),
        1,
        "exactly one result expected for one URL; got {}",
        results.len()
    );
    match &results[0] {
        Err(e) => e.to_string(),
        Ok(_) => panic!(
            "WebSource produced a CHUNK for {url}: it actually fetched a \
             non-public address, the strongest possible SSRF failure"
        ),
    }
}

/// Assert the guard REFUSED the URL up front (SSRF block) rather than attempting
/// an outbound connection. `refusing to fetch` is emitted only by the SSRF
/// pre-filter / resolution screen; `error sending request` is emitted only by
/// reqwest after a socket was opened.
fn assert_refused_before_connect(url: &str) {
    let err = fetch_error(url);
    assert!(
        err.contains("refusing to fetch"),
        "WebSource must REFUSE {url} as a non-public SSRF target before opening a \
         socket, but the error shows it tried to connect instead: {err}"
    );
    assert!(
        !err.contains("error sending request"),
        "WebSource opened a connection to {url} (SSRF guard bypassed): {err}"
    );
}

/// AUD-audit_hunts-1: 0.0.0.0/8 ("this network") is an SSRF target on Linux 
/// connecting to `0.1.2.3` routes to the local host, yet `is_disallowed_ipv4`
/// only blocks the single `0.0.0.0` via `is_unspecified()`, not the whole /8.
/// The verifier blocks the entire /8 (`bogon.rs:105` `v.octets()[0] == 0`).
/// FAILS NOW: WebSource attempts the connection. PASSES after the web path
/// adopts the bogon classifier.
#[test]
fn websource_blocks_zero_network_8_ssrf() {
    assert_refused_before_connect("http://0.1.2.3/app.js");
}

/// AUD-audit_hunts-2: Carrier-Grade NAT 100.64.0.0/10 (RFC 6598) is internal
/// infrastructure. The verifier refuses it (`bogon.rs:110`); WebSource does not
/// (`is_private()` is false for CGN). FAILS NOW: connection attempted.
#[test]
fn websource_blocks_carrier_grade_nat_ssrf() {
    assert_refused_before_connect("http://100.64.0.1/app.js");
}

/// AUD-audit_hunts-3: 198.18.0.0/15 (RFC 2544 benchmark) and 192.0.0.0/24
/// (RFC 6890 IETF protocol assignment) are non-public reserved ranges the
/// verifier refuses (`bogon.rs:113,116`). WebSource lets both through to a
/// real connection. FAILS NOW for both.
#[test]
fn websource_blocks_reserved_benchmark_and_ietf_ssrf() {
    assert_refused_before_connect("http://198.18.0.1/app.js");
    assert_refused_before_connect("http://192.0.0.1/app.js");
}

/// AUD-audit_hunts-4: 240.0.0.0/4 (RFC 1112 reserved / Class E) is not globally
/// routable. The verifier refuses the whole block fail-closed
/// (`ssrf.rs:102` `val & 0xF0000000 == 0xF0000000`). WebSource attempts the
/// connection. FAILS NOW.
#[test]
fn websource_blocks_class_e_reserved_ssrf() {
    assert_refused_before_connect("http://240.0.0.1/app.js");
}
