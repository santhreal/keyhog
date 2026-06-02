//! Adversarial test: IPv6 compat IPv4 loopback must classify as private.
//! Code path: bogon.rs line 136 `to_ipv4()` fallback for non-mapped addresses.
//! Contract: is_private_url must block [::127.0.0.1] (IPv4-compatible loopback).
//!
//! Note: IPv4-compatible addresses (::x.y.z.w) are deprecated per RFC 4291 but
//! still recognized by some resolvers. Mapped addresses (::ffff:x.y.z.w) are
//! explicitly checked first at line 133. Compat form falls through to to_ipv4().

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_ipv6_compat_loopback() {
    // IPv4-compatible (deprecated RFC 4291) form of 127.0.0.1
    // Parsed as Host::Ipv6, then bogon.rs calls to_ipv4() → Some(127.0.0.1)
    assert!(
        is_private_url("http://[::127.0.0.1]/"),
        "SSRF guard must block IPv6 compat-form loopback: http://[::127.0.0.1]/"
    );
}

#[test]
fn ssrf_blocks_ipv6_compat_rfc1918_10() {
    // IPv4-compatible form of 10.0.0.1
    assert!(
        is_private_url("http://[::10.0.0.1]/"),
        "SSRF guard must block IPv6 compat-form RFC1918 10.0.0.0/8: http://[::10.0.0.1]/"
    );
}

#[test]
fn ssrf_blocks_ipv6_compat_link_local_metadata() {
    // IPv4-compatible form of 169.254.169.254 (AWS/GCP IMDS)
    assert!(
        is_private_url("http://[::169.254.169.254]/"),
        "SSRF guard must block IPv6 compat-form metadata IP: http://[::169.254.169.254]/"
    );
}

#[test]
fn ssrf_blocks_ipv4_mapped_already_tested() {
    // Sanity check: mapped form (::ffff:...) already tested in existing suite
    // but document the distinction: mapped is checked explicitly at line 133,
    // compat falls through to line 136.
    assert!(
        is_private_url("http://[::ffff:127.0.0.1]/"),
        "SSRF guard must block IPv4-mapped loopback (existing test, documented): http://[::ffff:127.0.0.1]/"
    );
}
