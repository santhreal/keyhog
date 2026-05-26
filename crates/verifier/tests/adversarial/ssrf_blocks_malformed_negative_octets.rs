//! SSRF adversarial: negative octets must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_malformed_negative_octets() {
    assert!(
        is_private_url("http://-1.-1.-1.-1/"),
        "SSRF guard must block negative octets: http://-1.-1.-1.-1/"
    );
}
