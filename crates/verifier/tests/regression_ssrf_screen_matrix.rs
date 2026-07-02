//! Regression matrix for the verifier SSRF URL screen
//! ([`keyhog_verifier::ssrf::is_private_url`]).
//!
//! Every assertion pins the EXACT boolean the screen must return for a given
//! URL string. The screen is a fail-closed security gate: private / loopback /
//! link-local / metadata / integer-encoded / unparseable inputs must return
//! `true` (blocked), and only genuine public http(s) domains/IPs return `false`
//! (allowed to be verified). A single wrong bool here is a live SSRF hole, so
//! these are exact-value asserts, never shape checks.

use keyhog_verifier::ssrf::is_private_url;

// --------------------------------------------------------------------------
// TRUE (blocked) — private / loopback / reserved IPv4 literals
// --------------------------------------------------------------------------

#[test]
fn loopback_127_0_0_1_is_blocked() {
    assert_eq!(is_private_url("http://127.0.0.1"), true);
}

#[test]
fn private_10_0_0_1_is_blocked() {
    assert_eq!(is_private_url("http://10.0.0.1"), true);
}

#[test]
fn private_172_16_0_1_is_blocked() {
    assert_eq!(is_private_url("http://172.16.0.1"), true);
}

#[test]
fn private_192_168_1_1_is_blocked() {
    assert_eq!(is_private_url("http://192.168.1.1"), true);
}

#[test]
fn link_local_metadata_169_254_169_254_is_blocked() {
    // AWS/GCP/Azure link-local metadata address — the canonical SSRF target.
    assert_eq!(is_private_url("http://169.254.169.254"), true);
}

#[test]
fn unspecified_0_0_0_0_is_blocked() {
    assert_eq!(is_private_url("http://0.0.0.0"), true);
}

// --------------------------------------------------------------------------
// TRUE (blocked) — IPv6 literals
// --------------------------------------------------------------------------

#[test]
fn ipv6_loopback_bracketed_is_blocked() {
    assert_eq!(is_private_url("http://[::1]"), true);
}

#[test]
fn ipv6_unique_local_fc00_is_blocked() {
    // fc00::/7 unique-local — blocked via bogon is_unique_local().
    assert_eq!(is_private_url("http://[fc00::1]"), true);
}

// --------------------------------------------------------------------------
// TRUE (blocked) — integer-encoded loopback evasions
// --------------------------------------------------------------------------

#[test]
fn decimal_integer_loopback_2130706433_is_blocked() {
    // 2130706433 == 0x7f000001 == 127.0.0.1; dotless host is refused outright.
    assert_eq!(is_private_url("http://2130706433"), true);
}

#[test]
fn hex_integer_loopback_0x7f000001_is_blocked() {
    assert_eq!(is_private_url("http://0x7f000001"), true);
}

// --------------------------------------------------------------------------
// TRUE (blocked) — internal / metadata domain suffixes
// --------------------------------------------------------------------------

#[test]
fn metadata_google_internal_domain_is_blocked() {
    // Ends with ".internal" → GCP metadata host, blocked by suffix policy.
    assert_eq!(is_private_url("http://metadata.google.internal"), true);
}

// --------------------------------------------------------------------------
// FALSE (allowed) — genuine public destinations
// --------------------------------------------------------------------------

#[test]
fn public_dns_8_8_8_8_is_allowed() {
    assert_eq!(is_private_url("http://8.8.8.8"), false);
}

#[test]
fn public_domain_s3_amazonaws_com_is_allowed() {
    assert_eq!(is_private_url("https://s3.amazonaws.com"), false);
}

#[test]
fn public_domain_example_com_is_allowed() {
    assert_eq!(is_private_url("http://example.com"), false);
}

// --------------------------------------------------------------------------
// Adversarial / boundary twins — pin fail-closed behavior around the edges
// --------------------------------------------------------------------------

#[test]
fn unparseable_url_fails_closed_blocked() {
    // Law 10: an unparseable URL is treated as private, never allowed through.
    assert_eq!(is_private_url("not a url"), true);
}

#[test]
fn non_http_scheme_fails_closed_blocked() {
    // Only DNS-screenable http(s) URLs are permitted; file:// is refused.
    assert_eq!(is_private_url("file:///etc/passwd"), true);
    assert_eq!(is_private_url("ftp://example.com"), true);
}

#[test]
fn localhost_and_dotless_hosts_are_blocked() {
    // "localhost" and any dotless host cannot be safely resolved → blocked.
    assert_eq!(is_private_url("http://localhost"), true);
    assert_eq!(is_private_url("http://intranet"), true);
}

#[test]
fn short_form_inet_aton_loopback_is_blocked() {
    // 127.1 canonicalizes to 127.0.0.1 under inet_aton short-form rules.
    assert_eq!(is_private_url("http://127.1"), true);
    // 172.16.1 → 172.16.0.1 (3-part short form).
    assert_eq!(is_private_url("http://172.16.1"), true);
}

#[test]
fn https_scheme_public_ip_stays_allowed() {
    // Negative twin of the blocked-IP cases: a public IP over https is allowed
    // regardless of scheme, proving the block is address-driven not scheme-driven.
    assert_eq!(is_private_url("https://8.8.4.4"), false);
}
