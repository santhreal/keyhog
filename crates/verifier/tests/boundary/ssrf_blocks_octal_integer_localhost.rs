//! Boundary test: octal-encoded integer localhost (non-dotted) must classify as private.
//! Code path: ssrf.rs line 186-188 `starts_with('0')` and `from_str_radix(d, 8)` branch.
//! Contract: is_private_url must recognize octal 017700000001 as 127.0.0.1.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_octal_integer_localhost() {
    // Octal 017700000001 = decimal 2130706433 = 127.0.0.1
    // Existing test covers dotted octal (0177.0.0.1), this covers non-dotted integer form.
    assert!(
        is_private_url("http://017700000001/"),
        "SSRF guard must block octal-encoded localhost (non-dotted integer): http://017700000001/"
    );
}

#[test]
fn ssrf_blocks_octal_integer_rfc1918_10_net() {
    // Octal 0120000000001 = decimal 167772160 + 1 = 10.0.0.1
    assert!(
        is_private_url("http://0120000000001/"),
        "SSRF guard must block octal-encoded RFC1918 10.0.0.0/8: http://0120000000001/"
    );
}

#[test]
fn ssrf_blocks_octal_integer_link_local_metadata() {
    // Octal 0251376250376 = decimal 169.254.169.254 (AWS/GCP metadata)
    assert!(
        is_private_url("http://0251376250376/"),
        "SSRF guard must block octal-encoded link-local metadata: http://0251376250376/"
    );
}
