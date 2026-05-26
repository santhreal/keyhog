//! SSRF adversarial: RFC1918 172.16/12 must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_rfc1918_172_net() {
    assert!(
        is_private_url("http://172.16.0.1/"),
        "SSRF guard must block RFC1918 172.16/12: http://172.16.0.1/"
    );
}
