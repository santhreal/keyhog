//! SSRF adversarial: IPv6 loopback must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_ipv6_loopback() {
    assert!(
        is_private_url("http://[::1]/"),
        "SSRF guard must block IPv6 loopback: http://[::1]/"
    );
}
