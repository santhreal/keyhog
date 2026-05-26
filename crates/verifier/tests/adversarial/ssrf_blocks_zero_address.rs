//! SSRF adversarial: 0.0.0.0 must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_zero_address() {
    assert!(
        is_private_url("http://0.0.0.0/"),
        "SSRF guard must block 0.0.0.0: http://0.0.0.0/"
    );
}
