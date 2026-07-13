//! SSRF adversarial: the NAT64 well-known prefix (`64:ff9b::/96`, RFC 6052)
//! embeds an IPv4 address in its low 32 bits. An attacker who controls a URL the
//! verifier fetches can hide a private/metadata IPv4 inside a NAT64 IPv6 literal
//!: `http://[64:ff9b::169.254.169.254]/` reaches cloud IMDS on any host with a
//! NAT64 resolver, bypassing a guard that only screens dotted-quad IPv4. The
//! bogon classifier unwraps the embedded v4 and refuses it; these pin that.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_nat64_wrapped_aws_metadata() {
    // 64:ff9b::a9fe:a9fe == NAT64 wrapping 169.254.169.254 (IMDS).
    assert!(
        is_private_url("http://[64:ff9b::a9fe:a9fe]/latest/meta-data/"),
        "SSRF guard must block NAT64-wrapped cloud metadata: 64:ff9b::169.254.169.254"
    );
}

#[test]
fn ssrf_blocks_nat64_wrapped_rfc1918() {
    // 64:ff9b::a00:1 == NAT64 wrapping 10.0.0.1 (RFC 1918).
    assert!(
        is_private_url("http://[64:ff9b::a00:1]/"),
        "SSRF guard must block NAT64-wrapped RFC1918: 64:ff9b::10.0.0.1"
    );
}

#[test]
fn ssrf_blocks_nat64_wrapped_loopback() {
    // 64:ff9b::7f00:1 == NAT64 wrapping 127.0.0.1 (loopback).
    assert!(
        is_private_url("http://[64:ff9b::7f00:1]/"),
        "SSRF guard must block NAT64-wrapped loopback: 64:ff9b::127.0.0.1"
    );
}

#[test]
fn ssrf_allows_nat64_wrapped_public_ipv4() {
    // Negative twin: 64:ff9b::808:808 == NAT64 wrapping 8.8.8.8 (public). A NAT64
    // prefix around a globally routable IPv4 is a legitimate fetch target, so the
    // guard must NOT over-block it, refusing here would be a false positive that
    // silently kills real verification.
    assert!(
        !is_private_url("http://[64:ff9b::808:808]/"),
        "SSRF guard must allow NAT64-wrapped public IPv4 (8.8.8.8); over-blocking is a false positive"
    );
}
