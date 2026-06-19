//! Relocated unit tests for SSRF bogon classification.

use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[allow(clippy::too_many_arguments)]
fn v6(s0: u16, s1: u16, s2: u16, s3: u16, s4: u16, s5: u16, s6: u16, s7: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(s0, s1, s2, s3, s4, s5, s6, s7))
}

// ── IPv4: RFC 1918 + loopback + reserved ─────────────────────────────────

#[test]
fn rejects_rfc1918_10_8() {
    assert!(TestApi.ip_addr_is_bogon(v4(10, 0, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(10, 255, 255, 254)));
}

#[test]
fn rejects_rfc1918_172_16_12() {
    assert!(TestApi.ip_addr_is_bogon(v4(172, 16, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(172, 31, 255, 254)));
    assert!(!TestApi.ip_addr_is_bogon(v4(172, 32, 0, 1)));
}

#[test]
fn rejects_rfc1918_192_168_16() {
    assert!(TestApi.ip_addr_is_bogon(v4(192, 168, 1, 1)));
}

#[test]
fn rejects_loopback() {
    assert!(TestApi.ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    assert!(TestApi.ip_addr_is_bogon(v4(127, 1, 2, 3)));
}

#[test]
fn rejects_link_local() {
    assert!(TestApi.ip_addr_is_bogon(v4(169, 254, 0, 1)));
}

#[test]
fn rejects_imds_metadata_169_254_169_254() {
    assert!(TestApi.ip_addr_is_bogon(v4(169, 254, 169, 254)));
}

#[test]
fn rejects_unspecified_and_broadcast() {
    assert!(TestApi.ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    assert!(TestApi.ip_addr_is_bogon(IpAddr::V4(Ipv4Addr::BROADCAST)));
}

#[test]
fn rejects_documentation_and_test_net() {
    assert!(TestApi.ip_addr_is_bogon(v4(192, 0, 2, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(198, 51, 100, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(203, 0, 113, 1)));
}

#[test]
fn rejects_cgn_100_64_10() {
    assert!(TestApi.ip_addr_is_bogon(v4(100, 64, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(100, 127, 255, 254)));
    assert!(!TestApi.ip_addr_is_bogon(v4(100, 128, 0, 1)));
}

#[test]
fn rejects_ietf_protocol_assignment_192_0_0_24() {
    assert!(TestApi.ip_addr_is_bogon(v4(192, 0, 0, 1)));
}

#[test]
fn rejects_benchmark_198_18_15() {
    assert!(TestApi.ip_addr_is_bogon(v4(198, 18, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v4(198, 19, 0, 1)));
    assert!(!TestApi.ip_addr_is_bogon(v4(198, 20, 0, 1)));
}

#[test]
fn allows_public_ipv4_addresses() {
    assert!(!TestApi.ip_addr_is_bogon(v4(8, 8, 8, 8)));
    assert!(!TestApi.ip_addr_is_bogon(v4(1, 1, 1, 1)));
    assert!(!TestApi.ip_addr_is_bogon(v4(208, 67, 222, 222)));
}

// ── IPv6 ─────────────────────────────────────────────────────────────────

#[test]
fn rejects_ipv6_loopback() {
    assert!(TestApi.ip_addr_is_bogon(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

#[test]
fn rejects_ipv6_unique_local_fc00() {
    assert!(TestApi.ip_addr_is_bogon(v6(0xfc00, 0, 0, 0, 0, 0, 0, 1)));
    assert!(TestApi.ip_addr_is_bogon(v6(0xfd00, 0, 0, 0, 0, 0, 0, 1)));
}

#[test]
fn rejects_ipv6_link_local_fe80() {
    assert!(TestApi.ip_addr_is_bogon(v6(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
}

#[test]
fn rejects_ipv6_documentation_2001_db8() {
    assert!(TestApi.ip_addr_is_bogon(v6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));
}

#[test]
fn rejects_ipv6_teredo_2001_0000() {
    assert!(TestApi.ip_addr_is_bogon(v6(0x2001, 0x0000, 0, 0, 0, 0, 0, 1)));
}

#[test]
fn rejects_ipv6_orchidv2_2001_002x() {
    for x in 0u16..=0x000f {
        let s1 = 0x0020 | x;
        assert!(
            TestApi.ip_addr_is_bogon(v6(0x2001, s1, 0, 0, 0, 0, 0, 1)),
            "2001:{s1:04x}::/64 should be ORCHIDv2 bogon"
        );
    }
}

#[test]
fn rejects_ipv6_discard_100() {
    assert!(TestApi.ip_addr_is_bogon(v6(0x0100, 0, 0, 0, 0, 0, 0, 1)));
}

#[test]
fn rejects_ipv4_mapped_ipv6_for_private_v4() {
    let v6_addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001);
    assert!(TestApi.ip_addr_is_bogon(IpAddr::V6(v6_addr)));
}

#[test]
fn rejects_6to4_wrapping_private_v4() {
    let v6_addr = Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1);
    assert!(TestApi.ip_addr_is_bogon(IpAddr::V6(v6_addr)));
}

#[test]
fn allows_6to4_wrapping_public_v4() {
    let v6_addr = Ipv6Addr::new(0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 1);
    assert!(!TestApi.ip_addr_is_bogon(IpAddr::V6(v6_addr)));
}

#[test]
fn rejects_ipv6_multicast_and_unspecified() {
    assert!(TestApi.ip_addr_is_bogon(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    assert!(TestApi.ip_addr_is_bogon(v6(0xff00, 0, 0, 0, 0, 0, 0, 1)));
}

#[test]
fn allows_public_ipv6_addresses() {
    assert!(!TestApi.ip_addr_is_bogon(v6(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)));
    assert!(!TestApi.ip_addr_is_bogon(v6(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)));
}

#[test]
fn known_bogon_count_pinned_so_silent_removals_break_ci() {
    let known: &[IpAddr] = &[
        v4(10, 0, 0, 1),
        v4(172, 16, 0, 1),
        v4(192, 168, 1, 1),
        v4(127, 0, 0, 1),
        v4(169, 254, 169, 254),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        v4(192, 0, 2, 1),
        v4(100, 64, 0, 1),
        v4(192, 0, 0, 1),
        v4(198, 18, 0, 1),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        v6(0xfc00, 0, 0, 0, 0, 0, 0, 1),
        v6(0xfe80, 0, 0, 0, 0, 0, 0, 1),
        v6(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
        v6(0x2001, 0x0000, 0, 0, 0, 0, 0, 1),
        v6(0x2001, 0x0020, 0, 0, 0, 0, 0, 1),
        v6(0x0100, 0, 0, 0, 0, 0, 0, 1),
    ];
    for ip in known {
        assert!(TestApi.ip_addr_is_bogon(*ip), "{ip:?} expected to be bogon");
    }
    assert_eq!(known.len(), 18, "bogon coverage count changed");
}
