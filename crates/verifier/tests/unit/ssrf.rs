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
fn single_label_domain_is_private_url() {
    assert!(is_private_url("https://admin/"));
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

#[tokio::test]
async fn proxied_requests_block_unpinnable_internal_hostnames() {
    let single_label = TestApi
        .proxied_request_target_for_test("https://internal-router/", false, false)
        .await
        .expect_err("proxy path must not send single-label hosts to proxy DNS");
    assert_eq!(
        single_label,
        VerificationResult::Error("blocked: private URL".into())
    );

    let custom_domain = TestApi
        .proxied_request_target_for_test("https://api.corp/", false, false)
        .await
        .expect_err("proxy path must locally resolve and screen custom domains before proxying");
    match custom_domain {
        VerificationResult::Error(message) => assert!(
            message == "blocked: private URL"
                || message.starts_with("blocked: DNS resolution failed:"),
            "custom proxy target must fail closed, got {message}"
        ),
        other => panic!("custom proxy target must fail closed as Error, got {other:?}"),
    }

    for url in ["https://internal-router/", "https://api.corp/"] {
        TestApi
            .proxied_request_target_for_test(url, true, false)
            .await
            .expect("explicit private-IP allowance is required to proxy internal hostnames");
    }

    TestApi
        .proxied_request_target_for_test("https://example.com/", false, false)
        .await
        .expect("ordinary public domain remains proxy-verifiable");
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
