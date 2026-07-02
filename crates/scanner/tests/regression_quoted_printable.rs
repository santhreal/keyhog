//! Quoted-Printable decoder truth lock (distinct from
//! `regression_quoted_printable_soft_line_break.rs`, which focuses on the
//! soft-line-break variants, and from `regression_url_qp_html_decoders.rs`,
//! which drives the full decode pipeline). This file pins the byte-exact
//! semantics of the `=XX` hex-octet path, case handling, multibyte UTF-8
//! reassembly, invalid-UTF-8 rejection, literal passthrough, and end-to-end
//! recovery of a credential whose bytes were split behind QP escapes.
//!
//! Source under test:
//! `crates/scanner/src/decode/url.rs::quoted_printable_decode`
//! via the `keyhog_scanner::testing::quoted_printable_decode_for_test` seam,
//! which returns `Some(String)` on a valid UTF-8 decode and `None` when the
//! decoded bytes are not valid UTF-8.

#![cfg(feature = "decode")]

use keyhog_scanner::testing::quoted_printable_decode_for_test as qp;

/// Unwrap the successful (valid-UTF-8) decode path.
fn dec(s: &str) -> String {
    qp(s).expect("QP decode should yield valid UTF-8")
}

// ── `=XX` hex octet decodes to the exact byte ────────────────────────────────

#[test]
fn qp_hex_octet_decodes_to_exact_byte() {
    // `=41` is the byte 0x41 == 'A'.
    let out = dec("=41");
    assert_eq!(out, "A");
    assert_eq!(out.as_bytes(), &[0x41]);
}

#[test]
fn qp_hex_octet_lowercase_hex_digits() {
    // `=6b` -> 0x6B == 'k'. Lowercase hex digits are accepted.
    assert_eq!(dec("=6b"), "k");
}

#[test]
fn qp_hex_octet_mixed_and_upper_case_equivalent() {
    // Upper- and lower-case hex forms of the same octet decode identically.
    // 0x4A == 'J'.
    assert_eq!(dec("=4A"), "J");
    assert_eq!(dec("=4a"), "J");
}

#[test]
fn qp_three_hex_octets_in_sequence() {
    // 0x66='f', 0x6F='o', 0x6F='o'.
    assert_eq!(dec("=66=6F=6F"), "foo");
}

// ── `=3D` literal-equals and soft line break ─────────────────────────────────

#[test]
fn qp_equals_3d_is_a_literal_equals_byte() {
    // 0x3D == '='. A literal '=' in QP is always transmitted as `=3D`.
    let out = dec("=3D=3D");
    assert_eq!(out, "==");
    assert_eq!(out.as_bytes(), &[b'=', b'=']);
}

#[test]
fn qp_soft_line_break_bare_lf_removed() {
    // A raw `=` before a newline is a soft line break: the `=` and the LF are
    // both stripped so the wrapped value rejoins contiguously.
    assert_eq!(dec("key=\nvalue"), "keyvalue");
}

#[test]
fn qp_soft_line_break_crlf_removed() {
    assert_eq!(dec("key=\r\nvalue"), "keyvalue");
}

// ── Literal text passes through unchanged ────────────────────────────────────

#[test]
fn qp_plain_text_passthrough_unchanged() {
    assert_eq!(
        dec("just plain text, no escapes"),
        "just plain text, no escapes"
    );
}

#[test]
fn qp_non_hex_assignment_is_literal() {
    // `=s` is not a hex octet (`s` is not a hex digit), so the `=` stays literal
    // and a normal `HOST=server` assignment survives untouched.
    assert_eq!(dec("HOST=server"), "HOST=server");
}

#[test]
fn qp_space_and_tab_octets() {
    // 0x20 == space, 0x09 == tab.
    assert_eq!(dec("key=20name"), "key name");
    assert_eq!(dec("a=09b"), "a\tb");
}

// ── A secret behind `=XX` recovers end to end ────────────────────────────────

#[test]
fn qp_secret_behind_hex_octets_recovers() {
    // The first four bytes of an AWS access-key id are hidden as hex octets;
    // the tail is literal. The decoder must reassemble the full key id.
    // 0x41='A', 0x4B='K', 0x49='I', 0x41='A'.
    assert_eq!(dec("=41=4B=49=41IOSFODNN7EXAMPLE"), "AKIAIOSFODNN7EXAMPLE");
}

#[test]
fn qp_secret_split_across_soft_break_rejoins() {
    // A credential wrapped across a QP soft line break must reassemble as one
    // contiguous token, not `AKIA=` + newline + `IOSFODNN7EXAMPLE`.
    assert_eq!(dec("AKIA=\nIOSFODNN7EXAMPLE"), "AKIAIOSFODNN7EXAMPLE");
}

// ── Multibyte UTF-8 reassembly and invalid-UTF-8 rejection ────────────────────

#[test]
fn qp_multibyte_utf8_octets_decode() {
    // `=C3=A9` is the two-byte UTF-8 encoding of 'é' (U+00E9).
    let out = dec("=C3=A9");
    assert_eq!(out, "é");
    assert_eq!(out.as_bytes(), &[0xC3, 0xA9]);
}

#[test]
fn qp_invalid_utf8_octet_yields_none() {
    // A lone 0xFF byte is not valid UTF-8, so the whole decode fails closed.
    assert_eq!(qp("=FF"), None);
}

// ── Boundary / adversarial malformed inputs ──────────────────────────────────

#[test]
fn qp_truncated_single_hex_digit_is_literal() {
    // `=4` has only one trailing digit: the `=` is emitted literally.
    assert_eq!(dec("x=4"), "x=4");
}

#[test]
fn qp_non_hex_second_char_is_literal_equals() {
    // `=G0`: 'G' is not a hex digit, so the `=` is literal and "G0" passes through.
    assert_eq!(dec("=G0"), "=G0");
}

#[test]
fn qp_trailing_lone_equals_and_empty_input() {
    // A trailing bare `=` is a literal byte; empty input decodes to empty.
    assert_eq!(dec("secret="), "secret=");
    assert_eq!(dec(""), "");
}
