//! SSRF adversarial: URL-encoded 127.0.0.1 must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_url_encoded_loopback_ip() {
    assert!(
        is_private_url("http://%31%32%37%2e%30%2e%30%2e%31/"),
        "SSRF guard must block URL-encoded 127.0.0.1: http://%31%32%37%2e%30%2e%30%2e%31/"
    );
}
