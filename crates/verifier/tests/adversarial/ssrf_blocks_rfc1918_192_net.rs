//! SSRF adversarial: RFC1918 192.168/16 must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_rfc1918_192_net() {
    assert!(
        is_private_url("http://192.168.1.1/"),
        "SSRF guard must block RFC1918 192.168/16: http://192.168.1.1/"
    );
}
