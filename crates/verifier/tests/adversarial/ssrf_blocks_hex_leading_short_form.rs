//! SSRF adversarial: `0x`-hex-**leading** `inet_aton` short-form IPv4 hosts.
//!
//! glibc's `getaddrinfo` parses each dotted field with its own radix, so a
//! 2- or 3-part host whose *leading* field is `0x`-hex still canonicalizes to a
//! private/loopback target (`0x7f.1` → 127.0.0.1, `0xa9.0xfe.0xa9fe` →
//! 169.254.169.254). The pre-fix string gate stripped a whole-string `0x`
//! prefix first; the embedded dot then failed the integer parse and the host
//! never reached the per-field short-form canonicalizer. `looks_like_malformed_ip`
//! only fires at ≥4 parts, so these 2-/3-part forms reached neither gate — and on
//! the proxy verification path (no post-resolution IP veto) the string gate is
//! the *only* SSRF check. They must now be blocked.
//!
//! Octal-leading short forms (`0177.1`) already routed correctly because the
//! whole-string octal branch requires an all-digit host (the dot breaks it),
//! so they fell through to the canonicalizer. Only the `0x` whole-string strip
//! shadowed the dotted path. These tests pin the hex case and guard against the
//! fix over-blocking legitimate *public* hex short forms.

use keyhog_verifier::ssrf::is_private_url;

// ── hex-leading 2-part short forms → private/loopback ────────────────────────

#[test]
fn blocks_hex_two_part_loopback() {
    // 0x7f.1 -> 127 . (packed 1) -> 127.0.0.1 (loopback /8)
    assert!(
        is_private_url("http://0x7f.1/"),
        "0x7f.1 -> 127.0.0.1 must be blocked"
    );
}

#[test]
fn blocks_hex_two_part_loopback_no_trailing_slash() {
    assert!(
        is_private_url("http://0x7f.1"),
        "0x7f.1 (no path) -> 127.0.0.1 must be blocked"
    );
}

#[test]
fn blocks_hex_two_part_loopback_https() {
    assert!(
        is_private_url("https://0x7f.1/"),
        "https://0x7f.1/ -> 127.0.0.1 must be blocked"
    );
}

#[test]
fn blocks_uppercase_hex_prefix_two_part_loopback() {
    // 0X7f.1 (uppercase 0X) must strip the same as 0x.
    assert!(
        is_private_url("http://0X7f.1/"),
        "0X7f.1 -> 127.0.0.1 must be blocked"
    );
}

#[test]
fn blocks_uppercase_hex_digits_two_part_loopback() {
    // 0x7F.1 (uppercase hex digits) -> 127.0.0.1
    assert!(
        is_private_url("http://0x7F.1/"),
        "0x7F.1 -> 127.0.0.1 must be blocked"
    );
}

#[test]
fn blocks_hex_two_part_private_a() {
    // 0xa.1 -> 10 . (packed 1) -> 10.0.0.1 (private A /8)
    assert!(
        is_private_url("http://0xa.1/"),
        "0xa.1 -> 10.0.0.1 must be blocked"
    );
}

#[test]
fn blocks_hex_two_part_this_network_zero() {
    // 0x0.1 -> 0.0.0.1 ("this network" 0.0.0.0/8 — non-routable SSRF target)
    assert!(
        is_private_url("http://0x0.1/"),
        "0x0.1 -> 0.0.0.1 must be blocked"
    );
}

// ── hex-leading 3-part short forms → private/loopback/metadata ───────────────

#[test]
fn blocks_hex_three_part_loopback() {
    // 0x7f.0.1 -> 127 . 0 . (packed 1) -> 127.0.0.1
    assert!(
        is_private_url("http://0x7f.0.1/"),
        "0x7f.0.1 -> 127.0.0.1 must be blocked"
    );
}

#[test]
fn blocks_mixed_hex_octet_private_b() {
    // 0xac.0x10.1 -> 172 . 16 . (packed 1) -> 172.16.0.1 (private B /12)
    assert!(
        is_private_url("http://0xac.0x10.1/"),
        "0xac.0x10.1 -> 172.16.0.1 must be blocked"
    );
}

#[test]
fn blocks_hex_three_part_private_c() {
    // 0xc0.0xa8.1 -> 192 . 168 . (packed 1) -> 192.168.0.1 (private C /16)
    assert!(
        is_private_url("http://0xc0.0xa8.1/"),
        "0xc0.0xa8.1 -> 192.168.0.1 must be blocked"
    );
}

#[test]
fn blocks_hex_three_part_link_local() {
    // 0xa9.0xfe.1 -> 169 . 254 . (packed 1) -> 169.254.0.1 (link-local /16)
    assert!(
        is_private_url("http://0xa9.0xfe.1/"),
        "0xa9.0xfe.1 -> 169.254.0.1 must be blocked"
    );
}

#[test]
fn blocks_hex_short_form_cloud_metadata_imds() {
    // 0xa9.0xfe.0xa9fe -> 169 . 254 . (packed 0xa9fe=43518) -> 169.254.169.254
    // The AWS/GCP/Azure IMDS endpoint — the crown-jewel SSRF target.
    assert!(
        is_private_url("http://0xa9.0xfe.0xa9fe/"),
        "0xa9.0xfe.0xa9fe -> 169.254.169.254 (IMDS) must be blocked"
    );
}

#[test]
fn blocks_mixed_hex_octal_short_form_loopback() {
    // 0x7f.0177.1 -> 127 (hex) . 127 (octal 0177) . (packed 1) -> 127.127.0.1
    // 127.0.0.0/8 loopback covers the whole /8, so 127.127.0.1 is loopback.
    assert!(
        is_private_url("http://0x7f.0177.1/"),
        "0x7f.0177.1 -> 127.127.0.1 (loopback /8) must be blocked"
    );
}

// ── fix must NOT over-block legitimate PUBLIC hex short forms ────────────────

#[test]
fn allows_public_hex_two_part() {
    // 0x8.8 -> 8 . (packed 8) -> 8.0.0.8 (public)
    assert!(
        !is_private_url("http://0x8.8/"),
        "0x8.8 -> 8.0.0.8 is public and must not be blocked"
    );
}

#[test]
fn allows_public_hex_three_part() {
    // 0x8.0x8.8 -> 8 . 8 . (packed 8) -> 8.8.0.8 (public)
    assert!(
        !is_private_url("http://0x8.0x8.8/"),
        "0x8.0x8.8 -> 8.8.0.8 is public and must not be blocked"
    );
}

// ── 4-part hex forms stay blocked via looks_like_malformed_ip (unchanged) ────

#[test]
fn blocks_hex_four_part_loopback() {
    // 0x7f.0.0.1 — 4-part octet-shaped form caught by the malformed-IP heuristic.
    assert!(
        is_private_url("http://0x7f.0.0.1/"),
        "0x7f.0.0.1 (4-part) must be blocked"
    );
}

#[test]
fn blocks_all_hex_octets_four_part() {
    // 0xc0.0xa8.0x0.0x1 — every octet 0x-prefixed, 4 parts.
    assert!(
        is_private_url("http://0xc0.0xa8.0x0.0x1/"),
        "0xc0.0xa8.0x0.0x1 (4-part all-hex) must be blocked"
    );
}

#[test]
fn blocks_mixed_hex_octal_four_part() {
    // 0x7f.0177.0.1 — mixed radix, 4 parts.
    assert!(
        is_private_url("http://0x7f.0177.0.1/"),
        "0x7f.0177.0.1 (4-part mixed radix) must be blocked"
    );
}

// ── regression locks: the fix must preserve every prior block/allow ─────────

#[test]
fn still_blocks_dotless_hex_loopback() {
    // 0x7f000001 (no dots) -> 127.0.0.1 — blocked as before.
    assert!(
        is_private_url("http://0x7f000001/"),
        "dotless 0x7f000001 -> 127.0.0.1 must stay blocked"
    );
}

#[test]
fn still_blocks_dotless_decimal_loopback() {
    // 2130706433 (no dots) -> 127.0.0.1 — blocked as before.
    assert!(
        is_private_url("http://2130706433/"),
        "dotless 2130706433 -> 127.0.0.1 must stay blocked"
    );
}

#[test]
fn still_blocks_octal_leading_short_form() {
    // 0177.1 -> 127.0.0.1 — octal-leading path unchanged.
    assert!(
        is_private_url("http://0177.1/"),
        "0177.1 -> 127.0.0.1 must stay blocked"
    );
}

#[test]
fn still_blocks_decimal_two_part_short_form() {
    // 127.1 -> 127.0.0.1 — decimal short form unchanged.
    assert!(
        is_private_url("http://127.1/"),
        "127.1 -> 127.0.0.1 must stay blocked"
    );
}

#[test]
fn still_blocks_full_dotted_quad_loopback() {
    assert!(
        is_private_url("http://127.0.0.1/"),
        "127.0.0.1 quad must stay blocked"
    );
}

#[test]
fn still_blocks_full_dotted_quad_private() {
    assert!(
        is_private_url("http://10.0.0.1/"),
        "10.0.0.1 quad must stay blocked"
    );
}

#[test]
fn still_allows_public_decimal_short_form() {
    // 8.8 -> 8.0.0.8 (public) — must not be over-blocked.
    assert!(
        !is_private_url("http://8.8/"),
        "8.8 -> 8.0.0.8 public short form must stay allowed"
    );
}

#[test]
fn still_allows_public_dotted_quad() {
    assert!(
        !is_private_url("http://8.8.8.8/"),
        "8.8.8.8 public quad must stay allowed"
    );
}
