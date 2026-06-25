//! DNS/post-resolve SSRF: link-local 169.254.10.1

use keyhog_verifier::ssrf::is_private_ip_addr;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn dns_private_ip_link_local_v4() {
    let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 10, 1));
    assert!(
        is_private_ip_addr(&ip),
        "must classify link-local 169.254.10.1 as private"
    );
}
