//! SSRF adversarial: file:// URLs

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_file_scheme_url() {
    assert!(
        is_private_url("file:///etc/passwd"),
        "SSRF guard must block file:///etc/passwd"
    );
}
