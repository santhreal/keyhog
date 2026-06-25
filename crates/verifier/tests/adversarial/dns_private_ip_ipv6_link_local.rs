//! DNS/post-resolve SSRF: IPv6 fe80::1

use keyhog_verifier::ssrf::is_private_ip_addr;
use std::net::{IpAddr, Ipv6Addr};

#[test]
fn dns_private_ip_ipv6_link_local() {
    let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    assert!(
        is_private_ip_addr(&ip),
        "must classify IPv6 fe80::1 as private"
    );
}
