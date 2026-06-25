//! SSRF adversarial: IPv6 unspecified

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_ipv6_unspecified() {
    assert!(
        is_private_url("http://[::]/"),
        "SSRF guard must block http://[::]/"
    );
}
