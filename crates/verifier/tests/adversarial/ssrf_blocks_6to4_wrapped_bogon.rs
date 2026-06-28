//! SSRF adversarial: the 6to4 prefix (`2002::/16`, RFC 3056) embeds an IPv4
//! address in bits 16..48 (`2002:WWXX:YYZZ::`). Like NAT64, it lets an attacker
//! smuggle a private/metadata IPv4 inside an IPv6 literal — `2002:a9fe:a9fe::`
//! decodes to 169.254.169.254 (IMDS) — past a guard that only screens
//! dotted-quad. The bogon classifier unwraps the embedded v4 and refuses it when
//! the embedded address is itself a bogon; these pin that.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_6to4_wrapped_aws_metadata() {
    // 2002:a9fe:a9fe:: == 6to4 wrapping 169.254.169.254 (IMDS).
    assert!(
        is_private_url("http://[2002:a9fe:a9fe::]/latest/meta-data/"),
        "SSRF guard must block 6to4-wrapped cloud metadata: 2002:a9fe:a9fe:: (169.254.169.254)"
    );
}

#[test]
fn ssrf_blocks_6to4_wrapped_rfc1918() {
    // 2002:a00:1:: == 6to4 wrapping 10.0.0.1 (RFC 1918).
    assert!(
        is_private_url("http://[2002:a00:1::]/"),
        "SSRF guard must block 6to4-wrapped RFC1918: 2002:a00:1:: (10.0.0.1)"
    );
}

#[test]
fn ssrf_blocks_6to4_wrapped_loopback() {
    // 2002:7f00:1:: == 6to4 wrapping 127.0.0.1 (loopback).
    assert!(
        is_private_url("http://[2002:7f00:1::]/"),
        "SSRF guard must block 6to4-wrapped loopback: 2002:7f00:1:: (127.0.0.1)"
    );
}

#[test]
fn ssrf_allows_6to4_wrapped_public_ipv4() {
    // Negative twin: 2002:808:808:: == 6to4 wrapping 8.8.8.8 (public). A 6to4
    // address around a globally routable IPv4 is a legitimate fetch target, so
    // the guard must NOT over-block it.
    assert!(
        !is_private_url("http://[2002:808:808::]/"),
        "SSRF guard must allow 6to4-wrapped public IPv4 (8.8.8.8); over-blocking is a false positive"
    );
}
