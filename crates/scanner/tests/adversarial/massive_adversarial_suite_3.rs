//! Part 3 of massive, handwritten, deep adversarial integration test suite.
//!
//! Exclusively validates SSRF bogon checks, loopback evasion variations, DNS caches,
//! and verifier cache lookups.

use keyhog_verifier::ssrf::{is_private_ip_addr_fast, is_private_url};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// =========================================================================
// 1. SSRF BOGON AND LOOPBACK IP ADDRESS FAST CHECKS
// =========================================================================

#[test]
fn adv3_ssrf_ipv4_loopback_127_0_0_1_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_loopback_127_255_255_254_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_private_class_a_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(10, 5, 6, 7));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_private_class_b_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(172, 20, 30, 40));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_private_class_c_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 10, 20));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_link_local_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_unspecified_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_multicast_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 5));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_cgnat_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(100, 64, 5, 6));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_broadcast_must_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_loopback_must_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_unspecified_must_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_link_local_must_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_unique_local_must_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_multicast_must_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1));
    assert!(is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv4_public_must_not_be_private() {
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert!(!is_private_ip_addr_fast(&ip));
}

#[test]
fn adv3_ssrf_ipv6_public_must_not_be_private() {
    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
    assert!(!is_private_ip_addr_fast(&ip));
}

// =========================================================================
// 2. SSRF URL SCHEME AND DOMAIN EVASION CHECKS
// =========================================================================

#[test]
fn adv3_ssrf_url_localhost_domain_must_be_blocked() {
    assert!(is_private_url("http://localhost/verify"));
}

#[test]
fn adv3_ssrf_url_localhost_capitalized_must_be_blocked() {
    assert!(is_private_url("http://LOCALHOST/verify"));
}

#[test]
fn adv3_ssrf_url_dot_local_domain_must_be_blocked() {
    assert!(is_private_url("http://service.local/verify"));
}

#[test]
fn adv3_ssrf_url_dot_internal_domain_must_be_blocked() {
    assert!(is_private_url("http://database.internal/verify"));
}

#[test]
fn adv3_ssrf_url_dot_localdomain_must_be_blocked() {
    assert!(is_private_url("http://router.localdomain/verify"));
}

#[test]
fn adv3_ssrf_url_ipv4_loopback_dotted_must_be_blocked() {
    assert!(is_private_url("http://127.0.0.1/verify"));
}

#[test]
fn adv3_ssrf_url_ipv4_private_class_a_dotted_must_be_blocked() {
    assert!(is_private_url("http://10.0.0.1/verify"));
}

#[test]
fn adv3_ssrf_url_ipv4_private_class_b_dotted_must_be_blocked() {
    assert!(is_private_url("http://172.16.0.1/verify"));
}

#[test]
fn adv3_ssrf_url_ipv4_private_class_c_dotted_must_be_blocked() {
    assert!(is_private_url("http://192.168.1.1/verify"));
}

#[test]
fn adv3_ssrf_url_ipv6_loopback_bracketed_must_be_blocked() {
    assert!(is_private_url("http://[::1]/verify"));
}

#[test]
fn adv3_ssrf_url_ipv6_unspecified_bracketed_must_be_blocked() {
    assert!(is_private_url("http://[::]/verify"));
}

#[test]
fn adv3_ssrf_url_ipv4_decimal_integer_representation_must_be_blocked() {
    assert!(is_private_url("http://2130706433/verify")); // 127.0.0.1
}

#[test]
fn adv3_ssrf_url_ipv4_hex_representation_must_be_blocked() {
    assert!(is_private_url("http://0x7f000001/verify")); // 127.0.0.1
}

#[test]
fn adv3_ssrf_url_ipv4_hex_caps_representation_must_be_blocked() {
    assert!(is_private_url("http://0X7F000001/verify")); // 127.0.0.1
}

#[test]
fn adv3_ssrf_url_ipv4_octal_representation_must_be_blocked() {
    assert!(is_private_url("http://017700000001/verify")); // 127.0.0.1
}

#[test]
fn adv3_ssrf_url_ipv4_octal_dotted_representation_must_be_blocked() {
    assert!(is_private_url("http://0177.0.0.1/verify")); // 127.0.0.1 octal
}

#[test]
fn adv3_ssrf_url_ipv4_hex_dotted_representation_must_be_blocked() {
    // Malformed IP representation checks
    assert!(is_private_url("http://0x7f.0.0.1/verify"));
}

#[test]
fn adv3_ssrf_url_malformed_ip_with_negative_octets_must_be_blocked() {
    assert!(is_private_url("http://127.0.0.-1/verify"));
}

#[test]
fn adv3_ssrf_url_malformed_ip_with_too_many_dots_must_be_blocked() {
    assert!(is_private_url("http://127.0.0.0.1/verify"));
}

#[test]
fn adv3_ssrf_url_malformed_ip_with_hex_prefix_and_negative_must_be_blocked() {
    assert!(is_private_url("http://0x7f.0.0.-1/verify"));
}

#[test]
fn adv3_ssrf_url_public_domain_must_not_be_blocked() {
    assert!(!is_private_url("https://api.stripe.com/v1/charges"));
}

#[test]
fn adv3_ssrf_url_public_ip_dotted_must_not_be_blocked() {
    assert!(!is_private_url("http://8.8.8.8/verify"));
}
