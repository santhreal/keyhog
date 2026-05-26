//! SSRF adversarial: .localdomain suffix must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_localhost_localdomain() {
    assert!(
        is_private_url("http://localhost.localdomain/"),
        "SSRF guard must block .localdomain suffix: http://localhost.localdomain/"
    );
}
