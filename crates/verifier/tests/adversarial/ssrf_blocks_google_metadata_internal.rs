//! SSRF adversarial: metadata.google.internal must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_google_metadata_internal() {
    assert!(
        is_private_url("http://metadata.google.internal/"),
        "SSRF guard must block metadata.google.internal: http://metadata.google.internal/"
    );
}
