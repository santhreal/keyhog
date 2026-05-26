//! SSRF adversarial: too many octets must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_malformed_too_many_octets() {
    assert!(
        is_private_url("http://0.0.0.0.0/"),
        "SSRF guard must block too many octets: http://0.0.0.0.0/"
    );
}
