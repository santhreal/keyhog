//! Micro gate for `verifier/ssrf.rs` direct URL classification.

use keyhog_core::VerificationResult;
use keyhog_verifier::ssrf::{is_private_ip_addr, is_private_url};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

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

#[test]
fn nat64_resolved_loopback_is_blocked_by_shared_screen() {
    let url = "https://public.example/";
    let resolved = [SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::new(
            0x0064, 0xff9b, 0, 0, 0, 0, 0x7f00, 0x0001,
        )),
        443,
    )];

    let err = TestApi
        .ssrf_check_url_with_resolved_addrs_for_test(url, &resolved, false)
        .expect_err("NAT64 loopback mapping must be blocked after DNS resolution");
    assert_eq!(
        err,
        VerificationResult::Error("blocked: private URL".into())
    );
}

#[test]
fn pinned_request_client_cache_reuses_matching_dns_pin() {
    TestApi.clear_pinned_request_client_cache();
    let host = "cache-test.invalid";
    let addrs = [SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 443)];
    let timeout = Duration::from_millis(250);

    TestApi
        .pinned_request_client_for_test(host, &addrs, timeout, false)
        .expect("first pinned client builds");
    assert_eq!(TestApi.pinned_request_client_cache_len_for_host(host), 1);

    TestApi
        .pinned_request_client_for_test(host, &addrs, timeout, false)
        .expect("matching pinned client is reused");
    assert_eq!(
        TestApi.pinned_request_client_cache_len_for_host(host),
        1,
        "same host/address/security tuple must not rebuild a second cached client"
    );

    TestApi
        .pinned_request_client_for_test(host, &addrs, Duration::from_millis(500), false)
        .expect("timeout is part of the client cache key");
    assert_eq!(TestApi.pinned_request_client_cache_len_for_host(host), 2);
}
