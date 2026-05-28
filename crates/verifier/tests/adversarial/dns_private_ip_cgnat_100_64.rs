//! DNS/post-resolve SSRF: CGNAT 100.64.0.1

use keyhog_verifier::ssrf::is_private_ip_addr;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn dns_private_ip_cgnat_100_64() {
    let ip = IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1));
    assert!(is_private_ip_addr(&ip), "must classify CGNAT 100.64.0.1 as private");
}
