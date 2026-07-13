//! Adversarial test: mixed radix octets (hex + octal + decimal) must classify as private.
//! Code path: ssrf.rs line 214-229 `looks_like_malformed_ip()` heuristic.
//! Contract: is_private_url must reject domains that blend 0x, 0-prefixed octets, or negative markers
//! as evasion attempts that might decode to private IPs on permissive resolvers.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn ssrf_blocks_mixed_hex_octal_malformed() {
    // Octets: 0x7f (hex), 0177 (octal), 0 (decimal), 1 (decimal)
    // Single octet must be decimal, hex, or octal (not mixed with dots and different radix).
    // looks_like_malformed_ip line 222-229: >= 4 parts, all octet-shaped, has 0x/digit/- chars.
    assert!(
        is_private_url("http://0x7f.0177.0.1/"),
        "SSRF guard must block mixed radix octets: http://0x7f.0177.0.1/"
    );
}

#[test]
fn ssrf_blocks_mixed_hex_negative_malformed() {
    // Octets: 0x7f (hex), -1 (negative), 0 (decimal), 1 (decimal)
    assert!(
        is_private_url("http://0x7f.-1.0.1/"),
        "SSRF guard must block mixed radix with negative octet: http://0x7f.-1.0.1/"
    );
}

#[test]
fn ssrf_blocks_all_hex_octets_malformed() {
    // All octets prefixed 0x, each is a hex digit: 0x0.0x7.0x0.0x1, evasion attempt
    assert!(
        is_private_url("http://0x0.0x7.0x0.0x1/"),
        "SSRF guard must block all-hex-prefix octets: http://0x0.0x7.0x0.0x1/"
    );
}

#[test]
fn ssrf_blocks_mixed_octal_negative_malformed() {
    // Octets: 0177 (octal), -1 (negative), 0 (decimal), 1 (decimal)
    assert!(
        is_private_url("http://0177.-1.0.1/"),
        "SSRF guard must block mixed octal + negative octets: http://0177.-1.0.1/"
    );
}
