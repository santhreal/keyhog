//! SSRF adversarial: integer-encoded AWS metadata IP must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_aws_metadata_integer() {
    assert!(
        is_private_url("http://2852039166/latest/meta-data"),
        "SSRF guard must block integer-encoded AWS metadata IP: http://2852039166/latest/meta-data"
    );
}
