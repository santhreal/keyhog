//! SSRF adversarial: octal dotted localhost must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_octal_dotted_localhost() {
    assert!(
        is_private_url("http://0177.0.0.1/"),
        "SSRF guard must block octal dotted localhost: http://0177.0.0.1/"
    );
}
