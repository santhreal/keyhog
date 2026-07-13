//! Byte-exact contract for the binary source backend's C-string unescaper.
//!
//! Audit: KH-GAP, binary literal recall hardening (follows the two-assertion
//! `binary_literal_decode.rs`, which only pinned the 8-byte minimum and one
//! mixed hex+octal vector).
//!
//! ## Why this is recall-critical
//!
//! When keyhog scans a compiled binary, the `binary` backend recovers candidate
//! strings from the decompiler / `strings`-style output as C source fragments
//! e.g. `"AKIA\x41QYLPM..."`. Those fragments still carry C escape sequences.
//! [`extract_string_literals`] must decode each escape to the exact byte the
//! compiler originally emitted *before* the detectors run, because the detector
//! regexes match the literal secret bytes (`AKIAA...`), not the escaped source
//! form (`AKIA\x41...`). A single wrong byte, an octal value that fails to
//! wrap to `u8`, a hex escape that greedily eats a third digit, an escaped quote
//! that prematurely terminates the literal, silently corrupts the candidate and
//! the secret is missed with no error. That is invisible recall loss, the worst
//! failure mode for a scanner, so every escape-decoding edge is pinned here to
//! its exact output rather than to a shape check.
//!
//! These tests run only under `--features binary`; see the crate's `binary`
//! feature. They exercise the pure text-parsing path, no Ghidra subprocess and
//! no goblin object parsing (so they are deterministic and host-independent).
#![cfg(feature = "binary")]

use keyhog_sources::testing::{SourceTestApi, TestApi};

/// Extract every C string literal from one line of decompiled source.
fn lits(line: &str) -> Vec<String> {
    TestApi.extract_string_literals(line)
}

/// A typed empty result, asserting exact emptiness, not `is_empty()`, so the
/// failure diff shows what leaked through instead of a bare `false`.
fn none() -> Vec<String> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Hexadecimal byte escapes (`\xNN`)
// ---------------------------------------------------------------------------

#[test]
fn hex_two_digit_escape_decodes_to_single_byte() {
    assert_eq!(
        lits(r#"x = "AKIA\x41BCD123";"#),
        vec!["AKIAABCD123".to_string()],
        "\\x41 must decode to the byte 0x41 ('A') before detector matching"
    );
}

#[test]
fn hex_one_digit_escape_stops_at_non_hex() {
    assert_eq!(
        lits(r#"x = "prefix\x7suffix";"#),
        vec![format!("prefix{}suffix", '\u{7}')],
        "\\x7 followed by a non-hex char decodes the single hex digit 0x07"
    );
}

#[test]
fn hex_uppercase_digits_decode() {
    assert_eq!(
        lits(r#"x = "value\x4AONE9999";"#),
        vec!["valueJONE9999".to_string()],
        "\\x4A is the byte 0x4A ('J'); the following 'O' is a literal, not a 3rd digit"
    );
}

#[test]
fn hex_lowercase_digits_decode() {
    assert_eq!(
        lits(r#"x = "value\x6aone9999";"#),
        vec!["valuejone9999".to_string()],
        "lowercase hex digits decode identically to uppercase (0x6a == 'j')"
    );
}

#[test]
fn hex_escape_with_no_following_hex_digit_is_literal_backslash_x() {
    assert_eq!(
        lits(r#"x = "abcdefg\xZmore";"#),
        vec!["abcdefg\\xZmore".to_string()],
        "\\x with no hex digit must be preserved verbatim, not silently dropped"
    );
}

#[test]
fn hex_escape_caps_at_two_digits() {
    assert_eq!(
        lits(r#"x = "AAAA\x414BBBB";"#),
        vec!["AAAAA4BBBB".to_string()],
        "\\x414 is byte 0x41 ('A') then a literal '4', a hex escape never eats a 3rd digit"
    );
}

#[test]
fn hex_escape_at_string_end_with_no_digits_is_literal() {
    assert_eq!(
        lits(r#"x = "abcdefgh\x";"#),
        vec!["abcdefgh\\x".to_string()],
        "a trailing \\x with no hex digit before the close quote stays literal"
    );
}

// ---------------------------------------------------------------------------
// Octal byte escapes (`\N`, `\NN`, `\NNN`)
// ---------------------------------------------------------------------------

#[test]
fn octal_one_digit_escape_decodes() {
    assert_eq!(
        lits(r#"x = "abcdefg\7more";"#),
        vec![format!("abcdefg{}more", '\u{7}')],
        "\\7 is the single-digit octal byte 0o7 == 0x07"
    );
}

#[test]
fn octal_two_digit_escape_decodes() {
    assert_eq!(
        lits(r#"x = "abcdef\77more";"#),
        vec!["abcdef?more".to_string()],
        "\\77 is the two-digit octal byte 0o77 == 0x3F == '?'"
    );
}

#[test]
fn octal_three_digit_escape_wraps_to_u8() {
    assert_eq!(
        lits(r#"x = "abcdef\377more";"#),
        vec![format!("abcdef{}more", '\u{FF}')],
        "\\377 == 0o377 == 255 must land in a u8 (0xFF), not overflow or drop"
    );
}

#[test]
fn octal_escape_caps_at_three_digits() {
    assert_eq!(
        lits(r#"x = "AAAA\1234BBBB";"#),
        vec!["AAAAS4BBBB".to_string()],
        "\\1234 is 0o123 ('S') then a literal '4', octal never consumes a 4th digit"
    );
}

#[test]
fn octal_null_byte_escape_decodes() {
    assert_eq!(
        lits(r#"x = "abc\0def1234";"#),
        vec![format!("abc{}def1234", '\u{0}')],
        "\\0 followed by a non-octal char is the NUL byte, kept inside the value"
    );
}

#[test]
fn octal_value_decodes_to_ascii_letter() {
    assert_eq!(
        lits(r#"x = "\101BCDEFGH";"#),
        vec!["ABCDEFGH".to_string()],
        "\\101 == 0o101 == 65 == 'A'"
    );
}

// ---------------------------------------------------------------------------
// Unknown / simple escapes
// ---------------------------------------------------------------------------

#[test]
fn unknown_escape_letter_is_preserved_with_backslash() {
    assert_eq!(
        lits(r#"x = "abcdefg\zmore";"#),
        vec!["abcdefg\\zmore".to_string()],
        "an unrecognized escape keeps its backslash rather than vanishing"
    );
}

#[test]
fn unknown_escape_does_not_consume_following_character() {
    assert_eq!(
        lits(r#"x = "data\qZZZ999";"#),
        vec!["data\\qZZZ999".to_string()],
        "after an unknown escape the next char ('Z') is processed normally, not eaten"
    );
}

#[test]
fn simple_escapes_newline_tab_carriage_return_decode() {
    assert_eq!(
        lits(r#"x = "line1\n\tend\rXY";"#),
        vec!["line1\n\tend\rXY".to_string()],
        "\\n \\t \\r decode to their control bytes"
    );
}

#[test]
fn double_backslash_decodes_to_single_backslash() {
    assert_eq!(
        lits(r#"x = "path\\to\\fileX";"#),
        vec!["path\\to\\fileX".to_string()],
        "\\\\ collapses to one backslash, leaving following chars literal"
    );
}

// ---------------------------------------------------------------------------
// Quote handling inside literals (recall-critical termination edges)
// ---------------------------------------------------------------------------

#[test]
fn escaped_quote_does_not_terminate_the_literal() {
    assert_eq!(
        lits(r#"x = "ab\"cd1234ef";"#),
        vec!["ab\"cd1234ef".to_string()],
        "\\\" is an embedded quote byte; the literal continues to the next unescaped quote"
    );
}

#[test]
fn escaped_backslash_then_quote_does_terminate() {
    // `\\` is a complete escape (one backslash); the quote right after it is a
    // real, unescaped terminator. This is the mirror of the escaped-quote case
    // and proves the escape-skip counts pairs correctly.
    assert_eq!(
        lits(r#"x = "ab\\cd1234";"#),
        vec!["ab\\cd1234".to_string()],
        "after \\\\ the following quote terminates the literal"
    );
}

#[test]
fn trailing_lone_backslash_is_preserved() {
    // No closing quote at all; the literal runs to end-of-line and the dangling
    // backslash has no escape target, so it stays as a literal backslash.
    assert_eq!(
        lits("x = \"abcdefgh\\"),
        vec!["abcdefgh\\".to_string()],
        "a backslash at end-of-input is a literal backslash, not a panic or a drop"
    );
}

#[test]
fn trailing_escaped_quote_keeps_literal_open() {
    // `\"` at the very end escapes what would have been the closing quote, so the
    // literal is unterminated and the decoded quote byte is part of the value.
    assert_eq!(
        lits("x = \"abcdef12\\\""),
        vec!["abcdef12\"".to_string()],
        "a trailing \\\" decodes to a quote byte and does not close the literal"
    );
}

// ---------------------------------------------------------------------------
// Multiple literals / no literals
// ---------------------------------------------------------------------------

#[test]
fn multiple_literals_on_one_line_are_all_extracted() {
    assert_eq!(
        lits(r#"a = "first123"; b = "second456";"#),
        vec!["first123".to_string(), "second456".to_string()],
        "the scan continues past the first closing quote to find later literals"
    );
}

#[test]
fn line_without_quotes_yields_no_literals() {
    assert_eq!(
        lits(r#"const int x = 42;"#),
        none(),
        "a line with no string literal produces nothing"
    );
}

#[test]
fn empty_literal_yields_no_literals() {
    assert_eq!(
        lits(r#"x = "";"#),
        none(),
        "an empty literal is below the minimum and is dropped"
    );
}

// ---------------------------------------------------------------------------
// MIN_STRING_LEN boundary (checked on the RAW span AND the UNESCAPED bytes)
// ---------------------------------------------------------------------------

#[test]
fn minimum_length_is_inclusive_at_eight() {
    assert_eq!(
        lits(r#"x = "12345678";"#),
        vec!["12345678".to_string()],
        "exactly 8 bytes meets the binary literal minimum and is kept"
    );
}

#[test]
fn below_minimum_length_seven_is_dropped() {
    assert_eq!(
        lits(r#"x = "1234567";"#),
        none(),
        "7 raw bytes is under the minimum and never reaches the unescape/scan path"
    );
}

#[test]
fn raw_meets_minimum_but_unescaped_below_minimum_is_dropped() {
    // Raw span `\x41\x42\x43` is 12 chars (>= 8), but it decodes to "ABC"
    // (3 bytes < 8), so the post-unescape floor drops it. A decoded 3-byte
    // value is genuinely too short to be a secret.
    assert_eq!(
        lits(r#"x = "\x41\x42\x43";"#),
        none(),
        "the minimum is re-checked on the DECODED bytes, not just the raw span"
    );
}

#[test]
fn unescaped_exactly_minimum_from_escapes_is_kept() {
    assert_eq!(
        lits(r#"x = "\x41\x42\x43\x44\x45\x46\x47\x48";"#),
        vec!["ABCDEFGH".to_string()],
        "eight hex escapes decode to exactly 8 bytes and meet the floor"
    );
}

#[test]
fn unterminated_short_literal_is_dropped() {
    assert_eq!(
        lits("x = \"abc"),
        none(),
        "an unterminated literal under the minimum is dropped, not partially emitted"
    );
}

// ---------------------------------------------------------------------------
// Multibyte UTF-8 boundary safety (the str slice must stay on char boundaries)
// ---------------------------------------------------------------------------

#[test]
fn multibyte_utf8_inside_literal_is_boundary_safe() {
    assert_eq!(
        lits(r#"x = "café1234567";"#),
        vec!["café1234567".to_string()],
        "a 2-byte UTF-8 char inside the literal must not split the slice mid-codepoint"
    );
}

#[test]
fn four_byte_emoji_inside_literal_is_boundary_safe() {
    assert_eq!(
        lits(r#"x = "key😀rest12";"#),
        vec!["key😀rest12".to_string()],
        "a 4-byte UTF-8 char inside the literal is sliced on its boundary, not mid-byte"
    );
}
