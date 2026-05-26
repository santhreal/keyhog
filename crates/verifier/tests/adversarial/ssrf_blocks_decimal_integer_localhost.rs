//! SSRF adversarial: decimal integer localhost must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_decimal_integer_localhost() {
    assert!(
        is_private_url("http://2130706433/"),
        "SSRF guard must block decimal integer localhost: http://2130706433/"
    );
}
