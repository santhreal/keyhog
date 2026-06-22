//! Micro gate for `verifier/ssrf.rs` direct URL classification.

use keyhog_core::VerificationResult;
use keyhog_verifier::ssrf::{is_private_ip_addr, is_private_url};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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

#[test]
fn failed_integer_ip_parse_domain_is_blocked_by_resolved_ip_veto() {
    let url = "https://0xg.example/";
    assert!(
        !is_private_url(url),
        "a failed hex-integer parse must fall through as a domain so the DNS \
         post-resolution guard remains load-bearing"
    );

    let resolved = [SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443)];
    let err = TestApi
        .ssrf_check_url_with_resolved_addrs_for_test(url, &resolved, false)
        .expect_err("resolved loopback address must be blocked");
    assert_eq!(
        err,
        VerificationResult::Error("blocked: private URL".into()),
        "failed integer-IP parsing must not become an allow when DNS resolves private"
    );
    TestApi
        .ssrf_check_url_with_resolved_addrs_for_test(url, &resolved, true)
        .expect("explicit private-IP allowance is the only way to pass the injected resolution");
}
