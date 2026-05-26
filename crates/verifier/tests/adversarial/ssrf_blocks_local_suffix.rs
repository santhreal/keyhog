//! SSRF adversarial: .local suffix must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_local_suffix() {
    assert!(
        is_private_url("http://printer.local/"),
        "SSRF guard must block .local suffix: http://printer.local/"
    );
}
