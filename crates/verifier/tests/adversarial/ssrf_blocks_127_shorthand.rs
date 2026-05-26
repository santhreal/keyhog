//! SSRF adversarial: 127.1 loopback shorthand must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_127_shorthand() {
    assert!(
        is_private_url("http://127.1/"),
        "SSRF guard must block 127.1 loopback shorthand: http://127.1/"
    );
}
