//! Audit (VECTOR 7 — DEDUPLICATION): the WebSource SSRF IP-classification
//! predicate is a *forked* second copy of the fleet-canonical bogon predicate,
//! and the fork has diverged in coverage.
//!
//! ## The duplication
//!
//! There is a documented single source of truth for "is this address one an
//! SSRF guard must refuse?": the `bogon` crate, vendored into the verifier as
//! `crates/verifier/src/bogon.rs` (`mod bogon`). Its crate-level docs are
//! explicit:
//!
//!     "Consumers that need stricter rules (e.g. keyhog's verifier, which also
//!      blocks multicast and broadcast IPv4) should layer their additional
//!      checks on top of [`ip_addr_is_bogon`], **not fork it**."
//!     (crates/verifier/src/bogon.rs:56-64)
//!
//! The verifier follows that contract:
//!     `is_private_ip_addr(ip) = is_private_ip_addr_fast(ip) || bogon::ip_addr_is_bogon(*ip)`
//!     (crates/verifier/src/ssrf.rs:133-135)
//!
//! `crates/sources/src/web/ssrf.rs` does the opposite — it re-implements the
//! predicate by hand and does NOT reference `bogon` at all:
//!     - `is_disallowed_ipv4` (crates/sources/src/web/ssrf.rs:48-56)
//!     - `is_disallowed_ipv6` (crates/sources/src/web/ssrf.rs:58-71)
//!     - `is_disallowed_ip`   (crates/sources/src/web/ssrf.rs:73-78)
//!
//! The WebSource comments even acknowledge the canonical exists
//! ("the verifier already has this gate via bogon ... WebSource was the missing
//! surface", crates/sources/src/web.rs:128-130 and 195-200) yet a private copy
//! was written instead of depending on the shared crate. That is the Vector-7
//! defect: one predicate, two implementations, drifted apart.
//!
//! ## Why the drift is a real (security) defect, not cosmetics
//!
//! `is_disallowed_ipv4` is `is_loopback() || is_private() || is_link_local()
//! || is_multicast() || is_broadcast() || is_unspecified()`. That set is a
//! strict *subset* of what `bogon::ip_addr_is_bogon` blocks. The fork silently
//! lets through ranges the canonical refuses, so the WebSource SSRF gate can be
//! pointed at internal infrastructure the verifier would correctly block:
//!
//!     * 100.64.0.0/10  Carrier-Grade NAT (RFC 6598) — bogon blocks
//!                      (`octets[0]==100 && octets[1]&0xc0==0x40`,
//!                       crates/verifier/src/bogon.rs:121-123); `is_private()`
//!                       does NOT include CGN, so the fork returns `false`.
//!                      CGN space hosts real internal / provider services and
//!                      is a classic SSRF pivot.
//!     * 198.18.0.0/15  benchmarking (RFC 2544) — bogon blocks; fork misses.
//!     * 192.0.0.0/24   IETF protocol assignment — bogon blocks; fork misses.
//!     * 0.0.0.0/8      "this network" (RFC 1122) — bogon blocks the whole /8
//!                      (`v.octets()[0]==0`); the fork only matches the single
//!                      `0.0.0.0` via `is_unspecified()`, so `0.0.0.1` (a
//!                      real loopback alias on Linux) slips through.
//!
//! ## Expected fix
//!
//! Delete `is_disallowed_ipv4` / `is_disallowed_ipv6` in
//! crates/sources/src/web/ssrf.rs and route `is_disallowed_ip` through the
//! canonical `bogon` crate (add `bogon` as a `web`-gated dependency, mirroring
//! how the verifier consumes it), layering any sources-specific extra checks on
//! top — exactly as the bogon docs require. Once both call sites resolve to the
//! one canonical predicate, every assertion below passes.
//!
//! Tests use only the public, feature-gated `keyhog_sources::testing::is_disallowed_ip`
//! API (the `web` feature is on by default). They assert the concrete canonical
//! contract, not `bogon` internals.

#![cfg(feature = "web")]

use keyhog_sources::testing::is_disallowed_ip;
use std::net::{IpAddr, Ipv4Addr};

/// AUD-dedup-1 — Carrier-Grade NAT (100.64.0.0/10) must be refused.
///
/// The canonical `bogon::ip_addr_is_bogon` blocks 100.64.0.0/10
/// (crates/verifier/src/bogon.rs:121-123). The forked WebSource predicate
/// `is_disallowed_ipv4` (crates/sources/src/web/ssrf.rs:48-56) relies on
/// `Ipv4Addr::is_private()`, which excludes CGN, so it returns `false` and the
/// WebSource SSRF gate would happily fetch `http://100.64.0.1/...`.
///
/// FAILS NOW: `is_disallowed_ip(100.64.0.1)` returns `false`.
/// PASSES once `is_disallowed_ip` delegates to the canonical bogon predicate.
#[test]
fn cgn_100_64_is_refused_like_canonical_bogon() {
    let cgn = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
    assert!(
        is_disallowed_ip(cgn),
        "WebSource SSRF gate accepted CGN address {cgn} that the canonical \
         bogon predicate refuses (100.64.0.0/10, RFC 6598). The sources gate \
         is a forked copy of bogon that dropped this range — it must delegate \
         to the one canonical predicate."
    );
}

/// AUD-dedup-2 — every range the canonical bogon predicate refuses but the
/// forked sources predicate currently lets through.
///
/// Each address here is blocked by `bogon::ip_addr_is_bogon`
/// (crates/verifier/src/bogon.rs) and NOT by the forked
/// `is_disallowed_ipv4` (crates/sources/src/web/ssrf.rs:48-56). A single
/// canonical implementation would make both agree.
///
/// FAILS NOW on the first divergent address.
/// PASSES once the sources gate resolves to the canonical bogon predicate.
#[test]
fn forked_gate_matches_canonical_on_reserved_ranges() {
    // (address, RFC / range, bogon.rs evidence line)
    let must_refuse: &[(Ipv4Addr, &str)] = &[
        (Ipv4Addr::new(100, 64, 0, 1), "100.64.0.0/10 CGN (RFC 6598) — bogon.rs:121"),
        (Ipv4Addr::new(198, 18, 0, 1), "198.18.0.0/15 benchmark (RFC 2544) — bogon.rs:127"),
        (Ipv4Addr::new(192, 0, 0, 1), "192.0.0.0/24 IETF protocol assignment — bogon.rs:124"),
        (Ipv4Addr::new(0, 0, 0, 1), "0.0.0.0/8 this-network (RFC 1122) — bogon.rs:112"),
    ];

    let leaked: Vec<&str> = must_refuse
        .iter()
        .filter(|(ip, _)| !is_disallowed_ip(IpAddr::V4(*ip)))
        .map(|(_, why)| *why)
        .collect();

    assert!(
        leaked.is_empty(),
        "WebSource SSRF gate diverged from the canonical bogon predicate — it \
         accepted reserved/non-public ranges the canonical refuses:\n  {}\n\
         These two predicates must be the same single implementation \
         (delegate sources to the bogon crate).",
        leaked.join("\n  ")
    );
}

/// AUD-dedup-3 — sanity anchor: a genuinely public address must still be
/// allowed by BOTH the canonical and the (fixed) sources predicate. This
/// pins that the expected fix is "use the canonical bogon predicate", not
/// "block everything". `bogon` allows 8.8.8.8 (bogon.rs:90 doctest:
/// `assert!(!ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))))`), so a
/// correct delegation keeps this false.
///
/// PASSES NOW and must keep passing after the fix (guards against an
/// over-broad "block all" fix).
#[test]
fn public_address_remains_allowed() {
    let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert!(
        !is_disallowed_ip(public),
        "public address {public} must remain fetchable; the canonical bogon \
         predicate allows it, so delegating to bogon must not block it."
    );
}
