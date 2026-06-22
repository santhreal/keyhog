//! Gap coverage for the verifier SSRF guard.
//!
//! Targets the verifier predicates that decide whether live credential
//! verification is allowed to dial a host:
//!
//!   * `keyhog_verifier::ssrf::is_private_ip_addr_fast` — compatibility alias
//!     for the single verifier IP refusal policy.
//!   * `keyhog_verifier::ssrf::is_private_ip_addr` — the same single verifier
//!     IP refusal policy used after DNS resolution to defeat DNS rebinding.
//!   * `keyhog_verifier::ssrf::is_private_url` — the URL-string gate that parses
//!     the host through the `url` crate and refuses private / reserved / encoded
//!     loopback hosts (the only gate on the proxy verification path).
//!   * `keyhog_verifier::testing::ip_addr_is_bogon` — the shared bogon predicate.
//!
//! Every expected value here is derived directly from
//! `crates/verifier/src/ssrf.rs` + `crates/verifier/src/bogon.rs`. The verifier
//! policy is the fleet bogon table plus verifier-specific IPv4 multicast and
//! Class-E reserved refusals; `is_private_ip_addr_fast` must never drift into a
//! narrower duplicate table again.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use keyhog_verifier::ssrf::{is_private_ip_addr, is_private_ip_addr_fast, is_private_url};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

// --- small derivation helpers (not tests) ----------------------------------

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(
        s.parse::<Ipv6Addr>()
            .expect("test wrote a valid v6 literal"),
    )
}

// ===========================================================================
// is_private_ip_addr_fast — IPv4 loopback 127.0.0.0/8
// ===========================================================================

#[test]
fn fast_v4_loopback_network_base_and_one_blocked() {
    assert!(is_private_ip_addr_fast(&v4(127, 0, 0, 0)));
    assert!(is_private_ip_addr_fast(&v4(127, 0, 0, 1)));
}

#[test]
fn fast_v4_loopback_top_of_slash8_blocked() {
    // 127.255.255.255 is still inside 127/8.
    assert!(is_private_ip_addr_fast(&v4(127, 255, 255, 255)));
}

#[test]
fn fast_v4_loopback_lower_boundary_neighbor_allowed() {
    // 126.255.255.255 is one below 127/8 and is public.
    assert!(!is_private_ip_addr_fast(&v4(126, 255, 255, 255)));
}

#[test]
fn fast_v4_loopback_upper_boundary_neighbor() {
    // 128.0.0.0 is one above 127/8. Not loopback; not otherwise private => public.
    assert!(!is_private_ip_addr_fast(&v4(128, 0, 0, 0)));
}

// ===========================================================================
// is_private_ip_addr_fast — RFC1918 10/8, 172.16/12, 192.168/16
// ===========================================================================

#[test]
fn fast_v4_private_a_10_slash8() {
    assert!(is_private_ip_addr_fast(&v4(10, 0, 0, 0)));
    assert!(is_private_ip_addr_fast(&v4(10, 255, 255, 255)));
    // Neighbors are public.
    assert!(!is_private_ip_addr_fast(&v4(9, 255, 255, 255)));
    assert!(!is_private_ip_addr_fast(&v4(11, 0, 0, 0)));
}

#[test]
fn fast_v4_private_b_172_16_slash12_inside() {
    // 172.16.0.0 .. 172.31.255.255 inclusive.
    assert!(is_private_ip_addr_fast(&v4(172, 16, 0, 0)));
    assert!(is_private_ip_addr_fast(&v4(172, 31, 255, 255)));
    assert!(is_private_ip_addr_fast(&v4(172, 24, 13, 7)));
}

#[test]
fn fast_v4_private_b_172_16_slash12_boundaries_public() {
    // 172.15.x and 172.32.x are OUTSIDE the /12 and are public.
    assert!(!is_private_ip_addr_fast(&v4(172, 15, 255, 255)));
    assert!(!is_private_ip_addr_fast(&v4(172, 32, 0, 0)));
}

#[test]
fn fast_v4_private_c_192_168_slash16() {
    assert!(is_private_ip_addr_fast(&v4(192, 168, 0, 0)));
    assert!(is_private_ip_addr_fast(&v4(192, 168, 255, 255)));
    // 192.167.x and 192.169.x are public.
    assert!(!is_private_ip_addr_fast(&v4(192, 167, 255, 255)));
    assert!(!is_private_ip_addr_fast(&v4(192, 169, 0, 0)));
}

// ===========================================================================
// is_private_ip_addr_fast — link-local 169.254/16 + IMDS metadata
// ===========================================================================

#[test]
fn fast_v4_link_local_slash16() {
    assert!(is_private_ip_addr_fast(&v4(169, 254, 0, 0)));
    assert!(is_private_ip_addr_fast(&v4(169, 254, 255, 255)));
    // The cloud metadata address sits inside 169.254/16.
    assert!(is_private_ip_addr_fast(&v4(169, 254, 169, 254)));
    // 169.253.x and 169.255.x are public.
    assert!(!is_private_ip_addr_fast(&v4(169, 253, 255, 255)));
    assert!(!is_private_ip_addr_fast(&v4(169, 255, 0, 0)));
}

// ===========================================================================
// is_private_ip_addr_fast — unspecified 0/8
// ===========================================================================

#[test]
fn fast_v4_unspecified_slash8() {
    assert!(is_private_ip_addr_fast(&v4(0, 0, 0, 0)));
    assert!(is_private_ip_addr_fast(&v4(0, 255, 255, 255)));
    // 1.0.0.0 (a public Cloudflare/APNIC address) is NOT in 0/8.
    assert!(!is_private_ip_addr_fast(&v4(1, 0, 0, 0)));
}

// ===========================================================================
// is_private_ip_addr_fast — multicast 224/4 and reserved 240/4
// ===========================================================================

#[test]
fn fast_v4_multicast_slash4() {
    // 224.0.0.0 .. 239.255.255.255 inclusive.
    assert!(is_private_ip_addr_fast(&v4(224, 0, 0, 0)));
    assert!(is_private_ip_addr_fast(&v4(239, 255, 255, 255)));
    assert!(is_private_ip_addr_fast(&v4(230, 1, 2, 3)));
    // 223.255.255.255 is just below the multicast block => public.
    assert!(!is_private_ip_addr_fast(&v4(223, 255, 255, 255)));
}

#[test]
fn fast_v4_reserved_class_e_slash4() {
    // 240/4 is reserved; the guard fails closed across the whole block.
    assert!(is_private_ip_addr_fast(&v4(240, 0, 0, 0)));
    assert!(is_private_ip_addr_fast(&v4(250, 1, 2, 3)));
    // Limited broadcast 255.255.255.255 is the top host of 240/4.
    assert!(is_private_ip_addr_fast(&v4(255, 255, 255, 255)));
    // Decimal-IP evasion target 255.255.255.254 (== 4294967294) is reserved.
    assert!(is_private_ip_addr_fast(&v4(255, 255, 255, 254)));
}

// ===========================================================================
// is_private_ip_addr_fast — CGN 100.64/10
// ===========================================================================

#[test]
fn fast_v4_cgn_100_64_slash10_inside() {
    // 100.64.0.0 .. 100.127.255.255 inclusive.
    assert!(is_private_ip_addr_fast(&v4(100, 64, 0, 0)));
    assert!(is_private_ip_addr_fast(&v4(100, 127, 255, 255)));
    assert!(is_private_ip_addr_fast(&v4(100, 90, 39, 1)));
}

#[test]
fn fast_v4_cgn_100_64_slash10_boundaries_public() {
    // 100.63.x is below the /10 and 100.128.x is above it — both public.
    assert!(!is_private_ip_addr_fast(&v4(100, 63, 255, 255)));
    assert!(!is_private_ip_addr_fast(&v4(100, 128, 0, 0)));
    // 100.0.0.1 is in 100.0.0.0/24 (public), not CGN.
    assert!(!is_private_ip_addr_fast(&v4(100, 0, 0, 1)));
}

// ===========================================================================
// is_private_ip_addr_fast — public IPv4 must be allowed
// ===========================================================================

#[test]
fn fast_v4_public_addresses_allowed() {
    assert!(!is_private_ip_addr_fast(&v4(8, 8, 8, 8)));
    assert!(!is_private_ip_addr_fast(&v4(1, 1, 1, 1)));
    assert!(!is_private_ip_addr_fast(&v4(93, 184, 216, 34))); // example.com legacy
    assert!(!is_private_ip_addr_fast(&v4(140, 82, 121, 4))); // github.com-ish
}

// ===========================================================================
// is_private_ip_addr_fast — IPv6 loopback / unspecified / fe80 / fc00 / ff00
// ===========================================================================

#[test]
fn fast_v6_loopback_and_unspecified() {
    assert!(is_private_ip_addr_fast(&v6("::1")));
    assert!(is_private_ip_addr_fast(&v6("::")));
}

#[test]
fn fast_v6_link_local_fe80_slash10() {
    // fe80::/10 covers fe80.. through febf..
    assert!(is_private_ip_addr_fast(&v6("fe80::1")));
    assert!(is_private_ip_addr_fast(&v6("febf::1")));
    // fec0::/10 is deprecated site-local and is blocked by the shared bogon
    // layer through the single verifier policy.
    assert!(is_private_ip_addr_fast(&v6("fec0::1")));
}

#[test]
fn fast_v6_unique_local_fc00_slash7() {
    // fc00::/7 -> first byte 0xfc or 0xfd ((b & 0xfe) == 0xfc).
    assert!(is_private_ip_addr_fast(&v6("fc00::1")));
    assert!(is_private_ip_addr_fast(&v6("fd00::1")));
    assert!(is_private_ip_addr_fast(&v6("fdff:ffff::abcd")));
    // fb.. and fe.. are outside fc00::/7 for THIS rule.
    assert!(!is_private_ip_addr_fast(&v6("fbff::1")));
}

#[test]
fn fast_v6_multicast_ff00_slash8() {
    assert!(is_private_ip_addr_fast(&v6("ff00::1")));
    assert!(is_private_ip_addr_fast(&v6("ff02::1"))); // all-nodes link-local mcast
    assert!(is_private_ip_addr_fast(&v6("ffff::1")));
}

#[test]
fn fast_v6_public_addresses_allowed() {
    // Cloudflare + Google public resolvers.
    assert!(!is_private_ip_addr_fast(&v6("2606:4700:4700::1111")));
    assert!(!is_private_ip_addr_fast(&v6("2001:4860:4860::8888")));
    // Documentation 2001:db8:: is caught by the shared bogon layer through the
    // single verifier policy.
    assert!(is_private_ip_addr_fast(&v6("2001:db8::1")));
}

// ===========================================================================
// Compatibility alias: the historical fast name must equal the canonical
// post-resolution verifier IP refusal policy.
// ===========================================================================

#[test]
fn verifier_policy_v4_protocol_assignment_192_0_0_slash24() {
    // 192.0.0.0/24 is bogon (IETF protocol assignment) and must be blocked by
    // both public verifier IP predicates.
    assert!(is_private_ip_addr_fast(&v4(192, 0, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(192, 0, 0, 1)));
    assert!(is_private_ip_addr(&v4(192, 0, 0, 1)));
}

#[test]
fn verifier_policy_v4_benchmark_198_18_slash15() {
    // 198.18.0.0/15 benchmark range: bogon and blocked by both public verifier
    // IP predicates.
    assert!(is_private_ip_addr_fast(&v4(198, 18, 0, 1)));
    assert!(is_private_ip_addr_fast(&v4(198, 19, 255, 255)));
    assert!(TestApi.ip_addr_is_bogon(v4(198, 18, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(198, 19, 255, 255)));
    assert!(is_private_ip_addr(&v4(198, 18, 0, 1)));
    // 198.20.x is outside the /15 and is public on both layers.
    assert!(!TestApi.ip_addr_is_bogon(v4(198, 20, 0, 0)));
    assert!(!is_private_ip_addr(&v4(198, 20, 0, 0)));
}

#[test]
fn verifier_policy_v4_documentation_test_nets() {
    // RFC5737 TEST-NET-1/2/3 are documentation => bogon and verifier-blocked.
    for ip in [v4(192, 0, 2, 1), v4(198, 51, 100, 1), v4(203, 0, 113, 1)] {
        assert!(is_private_ip_addr_fast(&ip), "fast alias must flag {ip}");
        assert!(TestApi.ip_addr_is_bogon(ip), "bogon must flag {ip}");
        assert!(is_private_ip_addr(&ip), "combined must flag {ip}");
    }
}

#[test]
fn bogon_v4_broadcast_255() {
    // Limited broadcast: both layers agree (fast via 240/4, bogon via is_broadcast).
    assert!(is_private_ip_addr_fast(&v4(255, 255, 255, 255)));
    assert!(TestApi.ip_addr_is_bogon(v4(255, 255, 255, 255)));
    assert!(is_private_ip_addr(&v4(255, 255, 255, 255)));
}

// ===========================================================================
// ip_addr_is_bogon — IPv6 special wrappings & ranges
// ===========================================================================

#[test]
fn bogon_v6_ipv4_mapped_loopback() {
    // ::ffff:127.0.0.1 decomposes to v4 loopback => bogon.
    assert!(TestApi.ip_addr_is_bogon(v6("::ffff:127.0.0.1")));
    assert!(is_private_ip_addr(&v6("::ffff:127.0.0.1")));
}

#[test]
fn bogon_v6_ipv4_mapped_public_allowed() {
    // ::ffff:8.8.8.8 maps to a PUBLIC v4 => not bogon.
    assert!(!TestApi.ip_addr_is_bogon(v6("::ffff:8.8.8.8")));
    assert!(!is_private_ip_addr(&v6("::ffff:8.8.8.8")));
}

#[test]
fn bogon_v6_ipv4_compat_loopback() {
    // ::127.0.0.1 (deprecated compat form). to_ipv4() => 127.0.0.1 => bogon.
    assert!(TestApi.ip_addr_is_bogon(v6("::127.0.0.1")));
    assert!(is_private_ip_addr(&v6("::127.0.0.1")));
}

#[test]
fn bogon_v6_documentation_2001_db8_slash32() {
    assert!(TestApi.ip_addr_is_bogon(v6("2001:db8::1")));
    assert!(TestApi.ip_addr_is_bogon(v6("2001:db8:dead:beef::1")));
    assert!(is_private_ip_addr(&v6("2001:db8::1")));
    assert!(is_private_ip_addr_fast(&v6("2001:db8::1")));
}

#[test]
fn bogon_v6_teredo_2001_0000_slash32() {
    // 2001:0000::/32 Teredo.
    assert!(TestApi.ip_addr_is_bogon(v6("2001:0:abcd:ef01::1")));
    assert!(is_private_ip_addr(&v6("2001:0:abcd:ef01::1")));
}

#[test]
fn bogon_v6_orchidv2_2001_20_slash28() {
    // 2001:20::/28 => segs[1] & 0xfff0 == 0x0020.
    assert!(TestApi.ip_addr_is_bogon(v6("2001:20::1")));
    assert!(TestApi.ip_addr_is_bogon(v6("2001:2f::1"))); // 0x2f & 0xfff0 == 0x20
    assert!(is_private_ip_addr(&v6("2001:20::1")));
    // 2001:30:: => 0x30 & 0xfff0 == 0x30 != 0x20, and not docs/teredo => public.
    assert!(!TestApi.ip_addr_is_bogon(v6("2001:30::1")));
}

#[test]
fn bogon_v6_discard_prefix_100_slash64() {
    // 100::/64 discard prefix (RFC6666): segs[0..4] == 0x0100,0,0,0.
    assert!(TestApi.ip_addr_is_bogon(v6("100::1")));
    assert!(is_private_ip_addr(&v6("100::1")));
    // 100:0:0:1:: has a non-zero 4th segment => outside the /64 discard prefix.
    assert!(!TestApi.ip_addr_is_bogon(v6("100:0:0:1::1")));
}

#[test]
fn bogon_v6_6to4_wrapping_bogon_v4() {
    // 2002::/16 with embedded v4 = 10.0.0.1 (0x0a00.0001 -> segs[1]=0x0a00, segs[2]=0x0001).
    assert!(TestApi.ip_addr_is_bogon(v6("2002:a00:1::")));
    assert!(is_private_ip_addr(&v6("2002:a00:1::")));
    // 6to4 wrapping a PUBLIC v4 (8.8.8.8 -> 0x0808:0808) is not a bogon.
    assert!(!TestApi.ip_addr_is_bogon(v6("2002:808:808::")));
}

#[test]
fn bogon_v6_public_allowed() {
    assert!(!TestApi.ip_addr_is_bogon(v6("2606:4700:4700::1111")));
    assert!(!TestApi.ip_addr_is_bogon(v6("2001:4860:4860::8888")));
    assert!(!is_private_ip_addr(&v6("2606:4700:4700::1111")));
}

// ===========================================================================
// ip_addr_is_bogon — the ::1 regression (decomposes to 0.0.0.1, must be caught
// by the loopback short-circuit BEFORE the v4 fallback).
// ===========================================================================

#[test]
fn bogon_v6_loopback_regression_not_via_v4_fallback() {
    // ::1 -> to_ipv4() == 0.0.0.1 which is NOT 127/8; the is_loopback()
    // short-circuit is the load-bearing check.
    assert!(TestApi.ip_addr_is_bogon(v6("::1")));
    assert!(is_private_ip_addr(&v6("::1")));
    // ...but 0.0.0.1 itself, as a real v4 address, is caught by 0/8 anyway.
    assert!(TestApi.ip_addr_is_bogon(v4(0, 0, 0, 1)));
}

// ===========================================================================
// is_private_url — domain suffix blocklist
// ===========================================================================

#[test]
fn url_blocks_localhost_domain() {
    assert!(is_private_url("http://localhost/"));
    assert!(is_private_url("http://localhost:8080/path"));
}

#[test]
fn url_blocks_localhost_case_insensitive_via_url_normalization() {
    // The url crate lowercases the host for special schemes, so LOCALHOST
    // reaches the `d == "localhost"` check as "localhost".
    assert!(is_private_url("http://LOCALHOST/"));
    assert!(is_private_url("http://LocalHost/"));
}

#[test]
fn url_blocks_internal_local_localdomain_suffixes() {
    assert!(is_private_url("http://service.local/"));
    assert!(is_private_url("http://db.internal/"));
    assert!(is_private_url("http://host.localdomain/"));
    // Multi-label suffixes still match ends_with.
    assert!(is_private_url("http://a.b.c.internal/"));
}

#[test]
fn url_allows_public_domains() {
    assert!(!is_private_url("https://api.github.com/"));
    assert!(!is_private_url("https://example.com/"));
    assert!(!is_private_url("https://api.stripe.com/v1/charges"));
    // ".local" must be a suffix, not a substring: "local.example.com" is public.
    assert!(!is_private_url("https://local.example.com/"));
    // "internal" embedded as a label that is not the suffix is public.
    assert!(!is_private_url("https://internal.example.com/"));
}

// ===========================================================================
// is_private_url — malformed URL fails closed
// ===========================================================================

#[test]
fn url_malformed_blocked_fail_closed() {
    // Not parseable as a URL at all => block.
    assert!(is_private_url("not a url"));
    assert!(is_private_url(""));
    assert!(is_private_url("http://"));
    assert!(is_private_url("://missing-scheme"));
}

// ===========================================================================
// is_private_url — dotted-quad IPv4 in every guarded range
// ===========================================================================

#[test]
fn url_blocks_dotted_quad_private_ranges() {
    assert!(is_private_url("http://127.0.0.1/"));
    assert!(is_private_url("http://10.0.0.1/"));
    assert!(is_private_url("http://172.16.0.1/"));
    assert!(is_private_url("http://192.168.1.1/"));
    assert!(is_private_url("http://169.254.169.254/latest/meta-data/"));
    assert!(is_private_url("http://0.0.0.0/"));
    assert!(is_private_url("http://224.0.0.1/"));
    assert!(is_private_url("http://100.64.0.1/"));
}

#[test]
fn url_allows_dotted_quad_public() {
    assert!(!is_private_url("https://8.8.8.8/"));
    assert!(!is_private_url("https://1.1.1.1/"));
    assert!(!is_private_url("https://93.184.216.34/"));
}

// ===========================================================================
// is_private_url — integer / hex / octal encoded loopback (radix evasion)
// ===========================================================================

#[test]
fn url_blocks_decimal_integer_loopback() {
    // 2130706433 == 127.0.0.1. The url crate canonicalizes a bare numeric host
    // to Ipv4; either way the guard returns true.
    assert!(is_private_url("http://2130706433/"));
}

#[test]
fn url_blocks_decimal_integer_metadata() {
    // 2852039166 == 169.254.169.254 (AWS IMDS).
    assert!(is_private_url("http://2852039166/latest/meta-data"));
}

#[test]
fn url_blocks_hex_integer_loopback() {
    // 0x7f000001 == 127.0.0.1
    assert!(is_private_url("http://0x7f000001/"));
    assert!(is_private_url("http://0X7f000001/"));
}

#[test]
fn url_blocks_octal_integer_loopback() {
    // 017700000001 (octal) == 127.0.0.1
    assert!(is_private_url("http://017700000001/"));
}

#[test]
fn url_blocks_octal_dotted_loopback() {
    // 0177.0.0.1 — octal first octet == 127.
    assert!(is_private_url("http://0177.0.0.1/"));
}

#[test]
fn url_blocks_hex_dotted_loopback() {
    // 0x7f.0.0.1 — hex first octet == 127.
    assert!(is_private_url("http://0x7f.0.0.1/"));
}

#[test]
fn url_decimal_max_minus_one_is_reserved_blocked() {
    // 4294967294 == 255.255.255.254, inside reserved 240/4 => blocked.
    assert!(is_private_url("http://4294967294/"));
}

// ===========================================================================
// is_private_url — short-form (inet_aton) dotted IPv4
// ===========================================================================

#[test]
fn url_blocks_two_part_short_form_loopback() {
    // 127.1 -> 127.0.0.1
    assert!(is_private_url("http://127.1/"));
    assert!(is_private_url("http://127.1"));
}

#[test]
fn url_blocks_two_part_short_form_private_a() {
    // 10.1 -> 10.0.0.1
    assert!(is_private_url("http://10.1/"));
}

#[test]
fn url_blocks_three_part_short_form_private_b() {
    // 172.16.1 -> 172.16.0.1
    assert!(is_private_url("http://172.16.1/"));
}

#[test]
fn url_blocks_octal_two_part_short_form() {
    // 0177.1 -> octal 127 . 1 -> 127.0.0.1
    assert!(is_private_url("http://0177.1/"));
}

#[test]
fn url_allows_public_two_part_short_form() {
    // 8.8 -> 8.0.0.8, a public address. Must NOT be over-blocked.
    assert!(!is_private_url("http://8.8/"));
}

// ===========================================================================
// is_private_url — IPv6 literal hosts (bracketed)
// ===========================================================================

#[test]
fn url_blocks_ipv6_loopback_literal() {
    assert!(is_private_url("http://[::1]/"));
    assert!(is_private_url("http://[::1]:8443/admin"));
}

#[test]
fn url_blocks_ipv6_unspecified_literal() {
    assert!(is_private_url("http://[::]/"));
}

#[test]
fn url_blocks_ipv6_link_local_and_ula_literal() {
    assert!(is_private_url("http://[fe80::1]/"));
    assert!(is_private_url("http://[fc00::1]/"));
    assert!(is_private_url("http://[fd12:3456::1]/"));
}

#[test]
fn url_blocks_ipv6_mapped_and_compat_loopback_literal() {
    // Mapped and compat wrappings of loopback (bogon layer).
    assert!(is_private_url("http://[::ffff:127.0.0.1]/"));
    assert!(is_private_url("http://[::127.0.0.1]/"));
}

#[test]
fn url_blocks_ipv6_documentation_literal() {
    // 2001:db8:: documentation — caught via the bogon layer in is_private_url.
    assert!(is_private_url("http://[2001:db8::1]/"));
}

#[test]
fn url_allows_ipv6_public_literal() {
    assert!(!is_private_url("https://[2606:4700:4700::1111]/"));
    assert!(!is_private_url("https://[2001:4860:4860::8888]/"));
}

// ===========================================================================
// is_private_url — malformed-IP heuristic & spec-rejected hosts (DNS-rebind
// style evasion). The url crate REJECTS >4-part and negative-octet hosts, so
// is_private_url returns true via the malformed-URL fail-closed branch.
// ===========================================================================

#[test]
fn url_blocks_too_many_octets() {
    // 0.0.0.0.0 — five parts; url IPv4 parser fails => malformed URL => blocked.
    assert!(is_private_url("http://0.0.0.0.0/"));
}

#[test]
fn url_blocks_negative_octets() {
    // -1.-1.-1.-1 — rejected by the url host parser => blocked.
    assert!(is_private_url("http://-1.-1.-1.-1/"));
}

#[test]
fn url_blocks_mixed_radix_evasion_loopback() {
    // 0x7f.0177.0.1 — hex + octal blend resolving toward loopback territory.
    assert!(is_private_url("http://0x7f.0177.0.1/"));
}

#[test]
fn url_blocks_userinfo_loopback() {
    // Credentials in the authority must not smuggle a loopback host past the guard.
    assert!(is_private_url("http://user:pass@127.0.0.1/"));
    assert!(is_private_url("http://user:pass@localhost/"));
}

// ===========================================================================
// is_private_url — DNS rebinding intent: post-resolution IP veto.
// The string gate cannot see attacker.com's A record; the resolved-IP veto
// (is_private_ip_addr) is what defeats rebinding. Assert the resolved-IP layer
// catches private targets that a rebind would return.
// ===========================================================================

#[test]
fn dns_rebind_resolved_loopback_is_vetoed() {
    // A rebinding host resolves to 127.0.0.1 on the second lookup; the
    // post-resolution veto must reject it.
    assert!(is_private_ip_addr(&v4(127, 0, 0, 1)));
}

#[test]
fn dns_rebind_resolved_metadata_is_vetoed() {
    // attacker.com -> 169.254.169.254 (cloud IMDS) must be vetoed post-resolution.
    assert!(is_private_ip_addr(&v4(169, 254, 169, 254)));
}

#[test]
fn dns_rebind_resolved_public_is_allowed() {
    // A genuinely public resolution is allowed (no false veto).
    assert!(!is_private_ip_addr(&v4(8, 8, 8, 8)));
    assert!(!is_private_ip_addr(&v6("2606:4700:4700::1111")));
}

// ===========================================================================
// Property-style sweeps over the pure predicates (no I/O, fully derivable).
// ===========================================================================

#[test]
fn prop_v4_127_slash8_all_blocked() {
    // Every host inside 127/8 must be blocked by the fast path. Sample the
    // second-octet axis densely plus a stride over the low 16 bits.
    for b in 0u16..=255 {
        let ip = v4(127, b as u8, 0, 1);
        assert!(is_private_ip_addr_fast(&ip), "127.{b}.0.1 must be private");
    }
    for low in (0u32..=0xFFFF).step_by(257) {
        let c = (low >> 8) as u8;
        let d = (low & 0xFF) as u8;
        let ip = v4(127, 200, c, d);
        assert!(
            is_private_ip_addr_fast(&ip),
            "127.200.{c}.{d} must be private"
        );
    }
}

#[test]
fn prop_v4_172_16_slash12_membership_matches_definition() {
    // For 172.x.y.z, fast-path membership in the private-B test must agree with
    // the RFC definition x in [16,31] (other ranges of 172 are public unless
    // they coincide with another reserved block, which they do not here).
    for second in 0u16..=255 {
        let ip = v4(172, second as u8, 5, 9);
        let expect_private = (16..=31).contains(&second);
        assert_eq!(
            is_private_ip_addr_fast(&ip),
            expect_private,
            "172.{second}.5.9 private classification mismatch"
        );
    }
}

#[test]
fn prop_v4_cgn_100_64_slash10_membership() {
    // 100.64.0.0/10 == second octet in [64,127]. Outside that, 100.x is public
    // (none of 100.0/100.128.. overlaps another reserved block here).
    for second in 0u16..=255 {
        let ip = v4(100, second as u8, 1, 1);
        let expect_private = (64..=127).contains(&second);
        assert_eq!(
            is_private_ip_addr_fast(&ip),
            expect_private,
            "100.{second}.1.1 CGN classification mismatch"
        );
    }
}

#[test]
fn prop_v4_first_octet_reserved_blocks() {
    // Sweep the first octet with a fixed public-looking tail (x.123.45.67) and
    // assert the fast-path verdict matches the derived range table:
    //   0 (0/8), 10 (10/8), 100 (CGN only if 2nd octet in 64..=127 — here 123 -> private),
    //   127 (loopback), 169 (only 169.254 — here .123 -> public),
    //   172 (only .16..=.31 — here .123 -> public), 192 (only 192.168 — here .123 -> public),
    //   224..=255 (multicast+reserved). Everything else public.
    for first in 0u16..=255 {
        let ip = v4(first as u8, 123, 45, 67);
        let expect = match first {
            0 => true,         // 0/8
            10 => true,        // 10/8
            100 => true,       // 100.123 in CGN 100.64/10 (123 in 64..=127)
            127 => true,       // 127/8
            224..=255 => true, // multicast 224/4 + reserved 240/4
            _ => false,        // 169.123 / 172.123 / 192.123 are all public
        };
        assert_eq!(
            is_private_ip_addr_fast(&ip),
            expect,
            "{first}.123.45.67 fast verdict mismatch"
        );
    }
}

#[test]
fn prop_is_private_ip_addr_superset_of_fast() {
    // is_private_ip_addr = fast OR bogon, so it must be >= fast everywhere.
    // Sweep a representative grid; whenever fast says private, combined must too.
    for &first in &[
        0u8, 1, 8, 10, 100, 127, 169, 172, 192, 198, 203, 224, 240, 255,
    ] {
        for &second in &[0u8, 2, 16, 18, 64, 100, 168, 254] {
            let ip = v4(first, second, 0, 1);
            if is_private_ip_addr_fast(&ip) {
                assert!(
                    is_private_ip_addr(&ip),
                    "{first}.{second}.0.1 fast=private but combined=public (superset broken)"
                );
            }
        }
    }
}

#[test]
fn prop_url_public_hosts_never_blocked() {
    // A roster of legitimate public verification endpoints must all pass.
    for host in [
        "https://api.github.com/",
        "https://api.stripe.com/v1/account",
        "https://slack.com/api/auth.test",
        "https://www.googleapis.com/oauth2/v3/tokeninfo",
        "https://8.8.8.8/",
        "https://[2606:4700:4700::1111]/",
    ] {
        assert!(!is_private_url(host), "public host wrongly blocked: {host}");
    }
}

#[test]
fn prop_url_loopback_forms_all_blocked() {
    // Every encoding of 127.0.0.1 the guard claims to cover must be blocked.
    for host in [
        "http://127.0.0.1/",
        "http://127.1/",
        "http://0177.0.0.1/",
        "http://0x7f.0.0.1/",
        "http://2130706433/",
        "http://0x7f000001/",
        "http://017700000001/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::127.0.0.1]/",
        "http://localhost/",
    ] {
        assert!(is_private_url(host), "loopback form not blocked: {host}");
    }
}
