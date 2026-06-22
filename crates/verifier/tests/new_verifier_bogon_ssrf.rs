//! Standalone coverage for the verifier's SSRF-policy IP classification:
//! `bogon::ip_addr_is_bogon` (the canonical fleet-wide predicate) and the
//! verifier-local SSRF gate (`ssrf::is_private_ip_addr_fast`,
//! `is_private_ip_addr`, `is_private_url`).
//!
//! Every assertion pins a concrete verdict for a concrete address or URL:
//! "10.0.0.1 is a bogon", "8.8.8.8 is not", "http://0x7f000001/ is blocked".
//! No `is_ok()` / `!is_empty()` decoration. These are pure functions, so the
//! oracle is the RFC range each address falls in.

use keyhog_verifier::ssrf::{is_private_ip_addr, is_private_ip_addr_fast, is_private_url};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn v6(s: &str) -> IpAddr {
    IpAddr::V6(s.parse::<Ipv6Addr>().expect("valid IPv6 literal"))
}

// ===========================================================================
// bogon: IPv4 — each documented range must be refused
// ===========================================================================

#[test]
fn bogon_v4_rfc1918_private_a() {
    assert!(TestApi.ip_addr_is_bogon(v4(10, 0, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(10, 255, 255, 255)));
}

#[test]
fn bogon_v4_rfc1918_private_b() {
    assert!(TestApi.ip_addr_is_bogon(v4(172, 16, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(172, 31, 255, 254)));
    // 172.15 and 172.32 are OUTSIDE the /12 — must be allowed.
    assert!(!TestApi.ip_addr_is_bogon(v4(172, 15, 0, 1)));
    assert!(!TestApi.ip_addr_is_bogon(v4(172, 32, 0, 1)));
}

#[test]
fn bogon_v4_rfc1918_private_c() {
    assert!(TestApi.ip_addr_is_bogon(v4(192, 168, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(192, 168, 255, 254)));
}

#[test]
fn bogon_v4_loopback() {
    assert!(TestApi.ip_addr_is_bogon(v4(127, 0, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(127, 255, 255, 254)));
}

#[test]
fn bogon_v4_link_local_and_imds() {
    // 169.254.0.0/16 link-local, incl. the cloud metadata endpoint.
    assert!(TestApi.ip_addr_is_bogon(v4(169, 254, 0, 1)));
    assert!(
        TestApi.ip_addr_is_bogon(v4(169, 254, 169, 254)),
        "the AWS/GCP/Azure IMDS endpoint must be a bogon"
    );
}

#[test]
fn bogon_v4_broadcast() {
    assert!(TestApi.ip_addr_is_bogon(v4(255, 255, 255, 255)));
}

#[test]
fn bogon_v4_documentation_test_nets() {
    // TEST-NET-1/2/3 (RFC 5737).
    assert!(TestApi.ip_addr_is_bogon(v4(192, 0, 2, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(198, 51, 100, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(203, 0, 113, 1)));
}

#[test]
fn bogon_v4_this_network_zero_octet() {
    // 0.0.0.0/8 "this network" — not just 0.0.0.0.
    assert!(TestApi.ip_addr_is_bogon(v4(0, 0, 0, 0)));
    assert!(TestApi.ip_addr_is_bogon(v4(0, 0, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(0, 255, 1, 2)));
}

#[test]
fn bogon_v4_carrier_grade_nat() {
    // 100.64.0.0/10.
    assert!(TestApi.ip_addr_is_bogon(v4(100, 64, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(100, 127, 255, 254)));
    // 100.63 and 100.128 are OUTSIDE the /10.
    assert!(!TestApi.ip_addr_is_bogon(v4(100, 63, 255, 255)));
    assert!(!TestApi.ip_addr_is_bogon(v4(100, 128, 0, 1)));
}

#[test]
fn bogon_v4_ietf_protocol_assignment() {
    // 192.0.0.0/24.
    assert!(TestApi.ip_addr_is_bogon(v4(192, 0, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(192, 0, 0, 255)));
    // 192.0.1.0 is outside the /24.
    assert!(!TestApi.ip_addr_is_bogon(v4(192, 0, 1, 1)));
}

#[test]
fn bogon_v4_benchmark_range() {
    // 198.18.0.0/15.
    assert!(TestApi.ip_addr_is_bogon(v4(198, 18, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(198, 19, 255, 254)));
    // 198.17 and 198.20 are outside the /15.
    assert!(!TestApi.ip_addr_is_bogon(v4(198, 17, 0, 1)));
    assert!(!TestApi.ip_addr_is_bogon(v4(198, 20, 0, 1)));
}

#[test]
fn bogon_v4_public_addresses_are_allowed() {
    // Well-known public resolvers / hosts must NOT be bogons.
    assert!(!TestApi.ip_addr_is_bogon(v4(8, 8, 8, 8)));
    assert!(!TestApi.ip_addr_is_bogon(v4(1, 1, 1, 1)));
    assert!(!TestApi.ip_addr_is_bogon(v4(93, 184, 216, 34))); // example.com era
    assert!(!TestApi.ip_addr_is_bogon(v4(140, 82, 121, 4))); // github.com era
}

// ===========================================================================
// bogon: IPv6
// ===========================================================================

#[test]
fn bogon_v6_loopback_regression() {
    // The historic `::1` escape bug — must be a bogon.
    assert!(
        TestApi.ip_addr_is_bogon(v6("::1")),
        "::1 must be refused (the documented donor-copy regression)"
    );
    assert!(TestApi.ip_addr_is_bogon(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn bogon_v6_unspecified() {
    assert!(TestApi.ip_addr_is_bogon(v6("::")));
    assert!(TestApi.ip_addr_is_bogon(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
}

#[test]
fn bogon_v6_unique_local_and_link_local() {
    assert!(TestApi.ip_addr_is_bogon(v6("fc00::1"))); // unique-local fc00::/7
    assert!(TestApi.ip_addr_is_bogon(v6("fd12:3456::1"))); // unique-local
    assert!(TestApi.ip_addr_is_bogon(v6("fe80::1"))); // link-local fe80::/10
}

#[test]
fn bogon_v6_multicast() {
    assert!(TestApi.ip_addr_is_bogon(v6("ff02::1")));
}

#[test]
fn bogon_v6_documentation() {
    // 2001:db8::/32 (RFC 3849).
    assert!(TestApi.ip_addr_is_bogon(v6("2001:db8::1")));
    assert!(TestApi.ip_addr_is_bogon(v6("2001:db8:dead:beef::1")));
}

#[test]
fn bogon_v6_teredo() {
    // 2001:0000::/32 (RFC 4380).
    assert!(TestApi.ip_addr_is_bogon(v6("2001:0:1234::1")));
}

#[test]
fn bogon_v6_orchidv2() {
    // 2001:20::/28 (RFC 7343).
    assert!(TestApi.ip_addr_is_bogon(v6("2001:20::1")));
    assert!(TestApi.ip_addr_is_bogon(v6("2001:2f::1")));
}

#[test]
fn bogon_v6_discard_prefix() {
    // 100::/64 (RFC 6666).
    assert!(TestApi.ip_addr_is_bogon(v6("100::1")));
}

#[test]
fn bogon_v6_6to4_wrapping_bogon_v4() {
    // 2002::/16 wrapping 10.0.0.1 -> 2002:0a00:0001::
    assert!(
        TestApi.ip_addr_is_bogon(v6("2002:0a00:0001::1")),
        "6to4 wrapping a private v4 must be refused"
    );
    // 6to4 wrapping a PUBLIC v4 (8.8.8.8 -> 2002:0808:0808::) should NOT be a
    // bogon — it decodes to a routable address.
    assert!(!TestApi.ip_addr_is_bogon(v6("2002:0808:0808::1")));
}

#[test]
fn bogon_v6_ipv4_mapped_private() {
    // ::ffff:10.0.0.1 maps to a private v4 -> bogon.
    assert!(TestApi.ip_addr_is_bogon(v6("::ffff:10.0.0.1")));
    // ::ffff:8.8.8.8 maps to public -> not a bogon.
    assert!(!TestApi.ip_addr_is_bogon(v6("::ffff:8.8.8.8")));
}

#[test]
fn bogon_v6_public_is_allowed() {
    // Public IPv6 (Google DNS) must be allowed.
    assert!(!TestApi.ip_addr_is_bogon(v6("2001:4860:4860::8888")));
}

// ===========================================================================
// ssrf::is_private_ip_addr_fast — compatibility alias for the canonical verifier IP policy
// ===========================================================================

#[test]
fn fast_path_v4_private_and_loopback() {
    assert!(is_private_ip_addr_fast(&v4(127, 0, 0, 1)));
    assert!(is_private_ip_addr_fast(&v4(10, 1, 2, 3)));
    assert!(is_private_ip_addr_fast(&v4(172, 16, 0, 1)));
    assert!(is_private_ip_addr_fast(&v4(192, 168, 1, 1)));
    assert!(is_private_ip_addr_fast(&v4(169, 254, 0, 1)));
}

#[test]
fn fast_path_v4_multicast_and_reserved() {
    // 224.0.0.0/4 multicast.
    assert!(is_private_ip_addr_fast(&v4(224, 0, 0, 1)));
    // 240.0.0.0/4 reserved (Class E) — incl. .254 just below broadcast.
    assert!(is_private_ip_addr_fast(&v4(240, 0, 0, 1)));
    assert!(is_private_ip_addr_fast(&v4(255, 255, 255, 254)));
}

#[test]
fn fast_path_v4_cgn_and_unspecified() {
    assert!(is_private_ip_addr_fast(&v4(100, 64, 0, 1)));
    assert!(is_private_ip_addr_fast(&v4(0, 0, 0, 0)));
}

#[test]
fn fast_path_v4_public_is_not_private() {
    assert!(!is_private_ip_addr_fast(&v4(8, 8, 8, 8)));
    assert!(!is_private_ip_addr_fast(&v4(1, 1, 1, 1)));
}

#[test]
fn fast_path_v6_loopback_unspecified_local() {
    assert!(is_private_ip_addr_fast(&v6("::1")));
    assert!(is_private_ip_addr_fast(&v6("::")));
    assert!(is_private_ip_addr_fast(&v6("fe80::1")));
    assert!(is_private_ip_addr_fast(&v6("fc00::1")));
    assert!(is_private_ip_addr_fast(&v6("ff02::1")));
}

#[test]
fn fast_path_v6_public_is_not_private() {
    assert!(!is_private_ip_addr_fast(&v6("2001:4860:4860::8888")));
}

// ===========================================================================
// ssrf::is_private_ip_addr — the canonical post-resolution verifier IP policy
// ===========================================================================

#[test]
fn verifier_ip_policy_catches_bogon_ranges_through_both_public_names() {
    // 198.18.0.0/15 benchmark: shared bogon range, therefore blocked through
    // both public verifier IP predicates.
    assert!(
        is_private_ip_addr_fast(&v4(198, 18, 0, 1)),
        "fast compatibility alias must use the canonical verifier IP policy"
    );
    assert!(
        is_private_ip_addr(&v4(198, 18, 0, 1)),
        "post-resolution veto must refuse the benchmark range via the bogon layer"
    );
    // 192.0.2.0/24 documentation.
    assert!(is_private_ip_addr_fast(&v4(192, 0, 2, 1)));
    assert!(is_private_ip_addr(&v4(192, 0, 2, 1)));
}

#[test]
fn combined_veto_allows_public() {
    assert!(!is_private_ip_addr(&v4(8, 8, 8, 8)));
    assert!(!is_private_ip_addr(&v6("2001:4860:4860::8888")));
}

// ===========================================================================
// ssrf::is_private_url — URL-string SSRF gate
// ===========================================================================

#[test]
fn url_dotted_private_blocked() {
    assert!(is_private_url("http://127.0.0.1/"));
    assert!(is_private_url("https://10.0.0.1/path"));
    assert!(is_private_url("http://192.168.1.1:8080/"));
    assert!(is_private_url("http://169.254.169.254/latest/meta-data/"));
}

#[test]
fn url_public_allowed() {
    assert!(!is_private_url("https://8.8.8.8/"));
    assert!(!is_private_url("https://api.github.com/user"));
    assert!(!is_private_url("https://example.com/"));
}

#[test]
fn url_localhost_and_internal_tlds_blocked() {
    assert!(is_private_url("http://localhost/"));
    assert!(is_private_url("http://foo.local/"));
    assert!(is_private_url("http://svc.internal/"));
    assert!(is_private_url("http://host.localdomain/"));
}

#[test]
fn url_decimal_encoded_loopback_blocked() {
    // 2130706433 == 127.0.0.1
    assert!(
        is_private_url("http://2130706433/"),
        "decimal-encoded loopback must be blocked"
    );
}

#[test]
fn url_hex_encoded_loopback_blocked() {
    // 0x7f000001 == 127.0.0.1 (the VRF-001 bypass).
    assert!(
        is_private_url("http://0x7f000001/"),
        "hex-encoded loopback must be blocked"
    );
}

#[test]
fn url_octal_encoded_loopback_blocked() {
    // 017700000001 == 127.0.0.1
    assert!(
        is_private_url("http://017700000001/"),
        "octal-encoded loopback must be blocked"
    );
}

#[test]
fn url_short_form_loopback_blocked() {
    // 127.1 -> 127.0.0.1 (inet_aton 2-part form).
    assert!(
        is_private_url("http://127.1/"),
        "2-part short-form loopback must be blocked"
    );
}

#[test]
fn url_short_form_three_part_private_blocked() {
    // 172.16.1 -> 172.16.0.1 (3-part form).
    assert!(
        is_private_url("http://172.16.1/"),
        "3-part short-form private must be blocked"
    );
}

#[test]
fn url_ipv6_loopback_blocked() {
    assert!(is_private_url("http://[::1]/"));
}

#[test]
fn url_malformed_is_blocked_fail_closed() {
    // Unparseable URL — blocked fail-closed.
    assert!(
        is_private_url("not a url at all"),
        "a malformed URL must be blocked fail-closed"
    );
}

#[test]
fn url_hex_octet_malformed_ip_blocked() {
    // 0x7f.0.0.-1 style evasion (the looks_like_malformed_ip path).
    assert!(
        is_private_url("http://0x7f.0.0.1/"),
        "hex-octet dotted form must be blocked"
    );
}
