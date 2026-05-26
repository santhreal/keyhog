//! SSRF adversarial: URL-encoded localhost must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_url_encoded_localhost() {
    assert!(
        is_private_url("http://%6c%6f%63%61%6c%68%6f%73%74/"),
        "SSRF guard must block URL-encoded localhost: http://%6c%6f%63%61%6c%68%6f%73%74/"
    );
}
