//! SSRF adversarial: hex-encoded localhost must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_hex_localhost() {
    assert!(
        is_private_url("http://0x7f000001/"),
        "SSRF guard must block hex-encoded localhost: http://0x7f000001/"
    );
}
