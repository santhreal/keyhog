//! Recall lock for `crates/scanner/src/decode/url.rs::octal_escape_decode`.
//!
//! C octal escapes are 1–3 digits (`\1`, `\12`, `\101`), consumed greedily up to
//! three. The decoder previously required EXACTLY three digits: a short escape
//! (`\1`, `\12`), an escape truncated by a following non-octal char, or a
//! trailing `\`, all hit `.ok_or(())?` and returned `Err` for the WHOLE
//! candidate — silently dropping every OTHER octal escape in the string from the
//! decode-through path (all-or-nothing recall loss, the same class as the
//! `+`/`.` concat and quoted-printable soft-break bugs).
//!
//! The fix consumes 1–3 octal digits greedily, stopping at the first non-octal
//! char or end of input, and treats a non-octal-following `\` (including a
//! trailing one) as a literal backslash instead of aborting.
//!
//! Driven directly through the `keyhog_scanner::testing` facade so each case
//! asserts the exact decoded string.

#![cfg(feature = "decode")]

use keyhog_scanner::testing::octal_escape_decode_for_test as oct;

fn dec(s: &str) -> String {
    oct(s).expect("input has at least one octal escape")
}

// ── The bug: short / truncated escapes must decode, not abort ────────────────

#[test]
fn octal_two_digit_escape_decodes() {
    // `\12` == 0o12 == 10 == '\n'. Before the fix this returned Err.
    assert_eq!(dec(r"\12"), "\n");
}

#[test]
fn octal_one_digit_escape_decodes() {
    assert_eq!(dec(r"\1"), "\u{1}");
}

#[test]
fn octal_one_digit_escape_then_literal() {
    assert_eq!(dec(r"\1x"), "\u{1}x");
}

#[test]
fn octal_two_digit_escape_then_literal() {
    assert_eq!(dec(r"\11z"), "\tz");
}

#[test]
fn octal_greedy_caps_at_three_digits() {
    // `\1014` == `\101` ('A') + literal '4'.
    assert_eq!(dec(r"\1014"), "A4");
}

#[test]
fn octal_mixed_full_and_short_all_survive() {
    // The recall point: before the fix the short `\12` made the whole decode
    // Err, discarding the 'A' from `\101` too.
    assert_eq!(dec(r"\101\12"), "A\n");
}

#[test]
fn octal_short_escape_at_end_after_full_escapes() {
    // `\55` is a 2-digit escape at EOF; before the fix it read two digits, hit
    // EOF looking for a third, and Err'd — dropping "sk".
    assert_eq!(dec(r"\163\153\55"), "sk-");
}

#[test]
fn octal_full_then_short_then_full_interleaved() {
    assert_eq!(dec(r"\101\1\102"), "A\u{1}B");
}

// ── 3-digit escapes (regressions — must stay correct) ────────────────────────

#[test]
fn octal_three_digit_escapes_decode() {
    assert_eq!(dec(r"\101\102\103"), "ABC");
}

#[test]
fn octal_consecutive_full_escapes() {
    assert_eq!(dec(r"\101\102"), "AB");
}

#[test]
fn octal_realistic_secret_prefix() {
    // \163\153\55\160\162\157\152\55 == "sk-proj-".
    assert_eq!(dec(r"\163\153\55\160\162\157\152\55"), "sk-proj-");
}

#[test]
fn octal_space_escape() {
    assert_eq!(dec(r"\40"), " ");
}

#[test]
fn octal_two_digit_tab() {
    assert_eq!(dec(r"\11"), "\t");
}

// ── Boundary / overflow ──────────────────────────────────────────────────────

#[test]
fn octal_max_in_range_377() {
    assert_eq!(dec(r"\377"), "\u{ff}");
}

#[test]
fn octal_over_range_400_wraps_mod_256() {
    // 0o400 == 256 wraps to 0 in a u8, matching the common C convention.
    assert_eq!(dec(r"\400"), "\u{0}");
}

#[test]
fn octal_nul_single_digit() {
    assert_eq!(dec(r"\0"), "\u{0}");
}

#[test]
fn octal_nul_zero_padded() {
    assert_eq!(dec(r"\000"), "\u{0}");
}

// ── Literal backslash (non-octal-following `\`) ──────────────────────────────

#[test]
fn octal_trailing_backslash_is_literal_not_abort() {
    // `\101` ('A') then a trailing literal `\`. Before the fix the trailing `\`
    // returned Err and discarded the 'A'.
    assert_eq!(dec("\\101\\"), "A\\");
}

#[test]
fn octal_literal_backslash_before_escape_preserved() {
    // `\9` is a literal backslash+9 (9 is not an octal digit); the following
    // `\101` decodes to 'A' and the lazy prefix keeps the earlier "\9".
    assert_eq!(dec(r"\9\101"), "\\9A");
}

#[test]
fn octal_digit_eight_is_not_octal() {
    assert_eq!(dec(r"\8\101"), "\\8A");
}

// ── Negatives (no escape → nothing decoded → None) ───────────────────────────

#[test]
fn octal_no_backslash_returns_none() {
    assert_eq!(oct("hello world"), None);
}

#[test]
fn octal_empty_returns_none() {
    assert_eq!(oct(""), None);
}

#[test]
fn octal_backslash_eight_alone_returns_none() {
    // A lone `\8` has no octal escape and nothing else to decode.
    assert_eq!(oct(r"\8"), None);
}
