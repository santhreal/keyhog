//! Boundary test: uppercase HEX-encoded localhost must classify as private.
//! Code path: ssrf.rs line 183 `strip_prefix("0X")` branch.
//! Contract: is_private_url must recognize 0X (uppercase) hex prefix variant.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_uppercase_hex_localhost() {
    // 0x7f000001 is 127.0.0.1 in hex, tests lowercase variant (existing)
    // 0X7F000001 is 127.0.0.1 in hex with uppercase prefix and digits (gap)
    assert!(
        is_private_url("http://0X7F000001/"),
        "SSRF guard must block uppercase HEX-encoded localhost: http://0X7F000001/"
    );
}

#[test]
fn ssrf_blocks_mixed_case_hex_localhost() {
    // Variant: uppercase prefix, lowercase hex digits
    assert!(
        is_private_url("http://0x7F000001/"),
        "SSRF guard must block mixed-case HEX localhost: http://0x7F000001/"
    );
}

#[test]
fn ssrf_blocks_uppercase_hex_rfc1918_10_net() {
    // 0x0A000001 is 10.0.0.1 in hex
    assert!(
        is_private_url("http://0X0A000001/"),
        "SSRF guard must block uppercase HEX-encoded RFC1918 10.0.0.0/8: http://0X0A000001/"
    );
}
