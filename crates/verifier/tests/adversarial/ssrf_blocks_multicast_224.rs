//! SSRF adversarial: multicast 224.0.0.0/4

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_multicast_224() {
    assert!(
        is_private_url("http://224.0.0.1/"),
        "SSRF guard must block http://224.0.0.1/"
    );
}
