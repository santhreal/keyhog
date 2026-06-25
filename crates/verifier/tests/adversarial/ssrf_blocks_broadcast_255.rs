//! SSRF adversarial: IPv4 broadcast

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_broadcast_255() {
    assert!(
        is_private_url("http://255.255.255.255/"),
        "SSRF guard must block http://255.255.255.255/"
    );
}
