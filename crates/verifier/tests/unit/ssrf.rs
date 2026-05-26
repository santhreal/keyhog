//! Micro gate for `verifier/ssrf.rs` direct URL classification.

use keyhog_verifier::ssrf::{is_private_ip_addr, is_private_url};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn decimal_integer_localhost_is_private_url() {
    assert!(is_private_url("http://2130706433/"));
}

#[test]
fn hex_localhost_is_private_url() {
    assert!(is_private_url("http://0x7f000001/"));
}

#[test]
fn link_local_ip_addr_is_private() {
    assert!(is_private_ip_addr(&IpAddr::V4(Ipv4Addr::new(
        169, 254, 169, 254
    ))));
}

#[test]
fn public_ip_addr_is_not_private() {
    assert!(!is_private_ip_addr(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
}

#[test]
fn metadata_internal_domain_is_private_url() {
    assert!(is_private_url("http://metadata.google.internal/"));
}

#[test]
fn malformed_url_string_is_treated_as_private() {
    assert!(is_private_url("http://not a valid url"));
}
