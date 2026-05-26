//! SSRF adversarial: IPv4-mapped loopback must classify as private.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_ipv4_mapped_loopback() {
    assert!(
        is_private_url("http://[::ffff:127.0.0.1]/"),
        "SSRF guard must block IPv4-mapped loopback: http://[::ffff:127.0.0.1]/"
    );
}
