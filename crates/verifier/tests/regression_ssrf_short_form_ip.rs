//! Regression: `is_private_url` must block abbreviated (`inet_aton`) short-form
//! dotted IPv4 hosts (M19).
//!
//! glibc's `getaddrinfo` accepts 2- and 3-part dotted forms by packing the
//! trailing field into the low bytes (`127.1` → `127.0.0.1`, `10.1` →
//! `10.0.0.1`, `172.16.1` → `172.16.0.1`). The pre-fix string gate canonicalized
//! only full dotted-quads and bare integers, so these slipped through, and on
//! the proxy verification path (which skips the post-resolution IP veto) the
//! string gate is the *only* SSRF check. These cases must now resolve to their
//! private/loopback targets and be blocked.

use keyhog_verifier::ssrf::is_private_url;

#[test]
fn blocks_two_part_loopback_short_form() {
    // 127.1 -> 127.0.0.1 (loopback /8)
    assert!(
        is_private_url("http://127.1"),
        "127.1 -> 127.0.0.1 must be blocked"
    );
    assert!(
        is_private_url("https://127.1/"),
        "https://127.1/ must be blocked"
    );
}

#[test]
fn blocks_two_part_private_a_short_form() {
    // 10.1 -> 10.0.0.1 (private A /8)
    assert!(
        is_private_url("http://10.1"),
        "10.1 -> 10.0.0.1 must be blocked"
    );
}

#[test]
fn blocks_three_part_private_b_short_form() {
    // 172.16.1 -> 172.16.0.1 (private B /12)
    assert!(
        is_private_url("http://172.16.1"),
        "172.16.1 -> 172.16.0.1 must be blocked"
    );
}

#[test]
fn blocks_octal_short_form_loopback() {
    // 0177.1 -> 0o177 (=127) . packed-1 -> 127.0.0.1
    assert!(
        is_private_url("http://0177.1"),
        "0177.1 -> 127.0.0.1 must be blocked"
    );
}

#[test]
fn allows_public_short_form() {
    // 8.8 -> 8.0.0.8 is public; must NOT be flagged private by the short-form path.
    // (Guards against the canonicalizer over-blocking legitimate public hosts.)
    assert!(
        !is_private_url("http://8.8"),
        "8.8 -> 8.0.0.8 is public and must not be blocked"
    );
}

#[test]
fn full_dotted_quad_loopback_still_blocked() {
    // Existing behavior preserved off the bug path.
    assert!(is_private_url("http://127.0.0.1"));
    assert!(is_private_url("http://10.0.0.1"));
}
