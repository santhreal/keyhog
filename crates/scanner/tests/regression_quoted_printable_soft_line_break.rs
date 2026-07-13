//! Recall lock: `quoted_printable_decode` only removed the RFC2045 CRLF soft
//! line break (`=\r\n`). Real-world quoted-printable (Unix-origin MIME,
//! git-format-patch mail, many encoders) also wraps with a bare `=\n`, and
//! occasionally a lone `=\r`. Those fell through to the `=XX` hex path, failed,
//! and injected a spurious `=` + newline, so a secret a QP encoder wrapped
//! across a soft break was corrupted and lost. A literal `=` in QP is always
//! `=3D`, so a raw `=` before a newline is unambiguously a soft break: removing
//! all three variants is spec-correct and can never eat a real byte.
//!
//! QP decode is gated on `has_qp_escape` (a real `=<hex><hex>` must be present),
//! so a plain `FOO=\nBAR` config is never QP-decoded (this change is safe).
//!
//! Source under test: `crates/scanner/src/decode/url.rs::quoted_printable_decode`
//! via the `keyhog_scanner::testing` facade.

#![cfg(feature = "decode")]

use keyhog_scanner::testing::quoted_printable_decode_for_test as qp;

fn decoded(s: &str) -> String {
    qp(s).expect("valid UTF-8 QP decode")
}

// ── Soft line breaks (the fix) ───────────────────────────────────────────────

#[test]
fn qp_soft_break_bare_lf_removed() {
    // Before the fix: `=\n` became a literal `=` plus newline.
    assert_eq!(decoded("secret=\nvalue"), "secretvalue");
}

#[test]
fn qp_soft_break_crlf_removed() {
    assert_eq!(decoded("secret=\r\nvalue"), "secretvalue");
}

#[test]
fn qp_soft_break_lone_cr_removed() {
    assert_eq!(decoded("secret=\rvalue"), "secretvalue");
}

#[test]
fn qp_soft_break_bare_lf_at_end() {
    assert_eq!(decoded("secret=\n"), "secret");
}

#[test]
fn qp_soft_break_crlf_at_end() {
    assert_eq!(decoded("secret=\r\n"), "secret");
}

#[test]
fn qp_multiple_soft_breaks_all_removed() {
    assert_eq!(decoded("aaa=\nbbb=\nccc"), "aaabbbccc");
}

#[test]
fn qp_soft_break_rejoins_base64_fragments() {
    // The recall point: a base64 secret wrapped across a soft break must
    // reassemble contiguously.
    assert_eq!(decoded("QUtJQU=\nlPU0Y"), "QUtJQUlPU0Y");
}

#[test]
fn qp_soft_break_bare_lf_leading() {
    assert_eq!(decoded("=\nrest"), "rest");
}

#[test]
fn qp_soft_break_then_hex_octet() {
    assert_eq!(decoded("a=\n=42"), "aB");
}

#[test]
fn qp_hex_octet_then_soft_break() {
    assert_eq!(decoded("=41=\n=42"), "AB");
}

#[test]
fn qp_literal_equals_3d_then_soft_break() {
    // `=3D` is a literal `=`; the following `=\n` is a soft break.
    assert_eq!(decoded("x=3D=\ny"), "x=y");
}

// ── `=XX` hex octets (regressions, must stay correct) ───────────────────────

#[test]
fn qp_hex_octets_decode() {
    assert_eq!(decoded("=41=42=43"), "ABC");
}

#[test]
fn qp_hex_octets_lowercase_digits() {
    assert_eq!(decoded("=61=62"), "ab");
}

#[test]
fn qp_hex_octet_space_mixed_with_literal() {
    assert_eq!(decoded("foo=20bar"), "foo bar");
}

#[test]
fn qp_hex_octet_at_end() {
    assert_eq!(decoded("foo=41"), "fooA");
}

#[test]
fn qp_equals_3d_is_literal_equals() {
    assert_eq!(decoded("key=3Dvalue"), "key=value");
}

#[test]
fn qp_trailing_hex_octet_then_literal_equals() {
    assert_eq!(decoded("data=42="), "dataB=");
}

// ── Malformed / literal fallbacks (regressions) ──────────────────────────────

#[test]
fn qp_non_hex_after_equals_is_literal() {
    assert_eq!(decoded("a=zz b"), "a=zz b");
}

#[test]
fn qp_truncated_one_hex_digit_at_end_is_literal() {
    assert_eq!(decoded("foo=4"), "foo=4");
}

#[test]
fn qp_trailing_lone_equals_is_literal() {
    assert_eq!(decoded("secret="), "secret=");
}

#[test]
fn qp_only_equals_is_literal() {
    assert_eq!(decoded("="), "=");
}

#[test]
fn qp_empty_input() {
    assert_eq!(decoded(""), "");
}

#[test]
fn qp_plain_text_passthrough() {
    assert_eq!(decoded("plain text no escapes"), "plain text no escapes");
}
