//! Re-homed from the former inline `pinned_key_tests` in
//! `crates/verifier/src/verify/request.rs` — the `verify_request_no_inline_tests`
//! folder-contract gate forbids inline `#[cfg(test)]` there.
//!
//! Pins the pinned-client-cache KEY canonicalization (request.rs
//! `canonical_pinned_addrs`, added so a round-robin-DNS reorder of the same
//! A/AAAA set is ONE cache key — a HIT that reuses the reqwest Client + TLS pool
//! instead of rebuilding one per request — while a genuinely different IP set is
//! a distinct key, i.e. no false sharing). The private `PinnedClientKey` is
//! exercised through the `pinned_keys_equal_for_test` accessor so the type and
//! its fields stay module-private.

use keyhog_verifier::testing::{canonical_pinned_addrs, pinned_keys_equal_for_test};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

fn v4(a: u8, b: u8, c: u8, d: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), 443)
}

#[test]
fn canonicalization_is_independent_of_dns_order() {
    let a = v4(93, 184, 216, 34);
    let b = v4(93, 184, 216, 35);
    let c = v4(93, 184, 216, 36);
    let canon = canonical_pinned_addrs(&[a, b, c]);
    // Every permutation canonicalizes to the same Vec.
    assert_eq!(canon, canonical_pinned_addrs(&[c, b, a]));
    assert_eq!(canon, canonical_pinned_addrs(&[b, a, c]));
    assert_eq!(canon, canonical_pinned_addrs(&[c, a, b]));
}

#[test]
fn round_robin_reorder_is_a_key_hit_but_a_different_set_is_a_miss() {
    let a = v4(203, 0, 113, 1);
    let b = v4(203, 0, 113, 2);
    let c = v4(203, 0, 113, 3);
    let t = Duration::from_secs(5);
    // Same set, different DNS order => equal key (the cache HIT we want).
    assert!(pinned_keys_equal_for_test(
        "example.com",
        &[a, b, c],
        &[c, a, b],
        t,
        false
    ));
    // A genuinely different IP set => distinct key (no false sharing).
    assert!(!pinned_keys_equal_for_test(
        "example.com",
        &[a, b, c],
        &[a, b],
        t,
        false
    ));
    assert!(!pinned_keys_equal_for_test(
        "example.com",
        &[a, b, c],
        &[a, b, v4(203, 0, 113, 9)],
        t,
        false
    ));
}

#[test]
fn mixed_v4_v6_canonicalizes_stably() {
    let v4a = v4(198, 51, 100, 7);
    let v6a = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        443,
    );
    assert_eq!(
        canonical_pinned_addrs(&[v4a, v6a]),
        canonical_pinned_addrs(&[v6a, v4a]),
        "a mixed v4/v6 set is order-independent too"
    );
}
