//! Boundary contract for the three isolated-bare candidate SHAPE gates in
//! `entropy/isolated.rs` — the keyword-free admission gates that decide whether
//! a bare token is even shaped like an opaque secret before the entropy floors
//! run. Each carries hand-tuned magic lengths/counts (colon halves >=20/>=16,
//! symbolic-alpha len>=18 + punctuation>=3 + alpha*2>=len, symbolic-bare
//! symbol_count>=2) and had no direct tests, so a future edit could silently
//! widen or narrow recall. These tests pin every threshold and char-class.
//!
//! `symbolic_alpha_only_opaque` depends on the random-vs-dictionary token check;
//! tests that hinge on it self-validate the precondition via `is_random_token`
//! so a model change fails loudly here, not silently in the gate.

use keyhog_scanner::testing::entropy_isolated::{
    colon_separated_opaque, is_random_token, symbolic_alpha_only_opaque, symbolic_bare,
};

// ── colon_separated_opaque_candidate ────────────────────────────────────────
// Exactly one ':', not '://', left half >=20 and right half >=16, each
// all-alphanumeric with at least one letter AND one digit.

/// left = 20 alnum (letters + digits), right = 16 alnum (letters + digits).
const COLON_OK: &str = "abcdefghij0123456789:klmnopqr01234567";

#[test]
fn colon_separated_positive() {
    assert!(colon_separated_opaque(COLON_OK));
}

#[test]
fn colon_separated_left_19_too_short_fails() {
    assert!(!colon_separated_opaque(
        "abcdefghij012345678:klmnopqr01234567"
    ));
}

#[test]
fn colon_separated_right_15_too_short_fails() {
    assert!(!colon_separated_opaque(
        "abcdefghij0123456789:klmnopqr0123456"
    ));
}

#[test]
fn colon_separated_two_colons_fails() {
    assert!(!colon_separated_opaque(
        "abcdefghij0123456789:klmnopqr012345:7"
    ));
}

#[test]
fn colon_separated_scheme_separator_fails() {
    assert!(!colon_separated_opaque(
        "abcdefghij012345678://mnopqr01234567ab"
    ));
}

#[test]
fn colon_separated_left_without_digit_fails() {
    // left is 20 letters, no digit.
    assert!(!colon_separated_opaque(
        "abcdefghijklmnopqrst:klmnopqr01234567"
    ));
}

#[test]
fn colon_separated_right_without_letter_fails() {
    // right is 16 digits, no letter.
    assert!(!colon_separated_opaque(
        "abcdefghij0123456789:0123456789012345"
    ));
}

#[test]
fn colon_separated_non_alphanumeric_in_half_fails() {
    // left contains '-'.
    assert!(!colon_separated_opaque(
        "abcdefghij01234567-9:klmnopqr01234567"
    ));
}

#[test]
fn colon_separated_no_colon_fails() {
    assert!(!colon_separated_opaque(
        "abcdefghij0123456789klmnopqr01234567"
    ));
}

#[test]
fn colon_separated_empty_fails() {
    assert!(!colon_separated_opaque(""));
}

// ── symbolic_bare (symbolic_isolated_bare_candidate) ────────────────────────
// No '://', no ':' or ',', every byte ASCII-graphic and not a quote, at least
// two non-alphanumeric symbol bytes.

#[test]
fn symbolic_bare_positive() {
    assert!(symbolic_bare("abc-def_ghi"));
}

#[test]
fn symbolic_bare_exactly_two_symbols() {
    assert!(symbolic_bare("ab-cd_ef"));
}

#[test]
fn symbolic_bare_one_symbol_fails() {
    assert!(!symbolic_bare("abc-defghi"));
}

#[test]
fn symbolic_bare_zero_symbols_fails() {
    assert!(!symbolic_bare("abcdefghij"));
}

#[test]
fn symbolic_bare_colon_fails() {
    assert!(!symbolic_bare("abc:def-ghi"));
}

#[test]
fn symbolic_bare_comma_fails() {
    assert!(!symbolic_bare("abc,def-ghi"));
}

#[test]
fn symbolic_bare_scheme_separator_fails() {
    assert!(!symbolic_bare("ab://cd-ef"));
}

#[test]
fn symbolic_bare_quote_fails() {
    assert!(!symbolic_bare("abc-\"def\""));
}

#[test]
fn symbolic_bare_space_non_graphic_fails() {
    assert!(!symbolic_bare("abc - def"));
}

#[test]
fn symbolic_bare_many_symbols() {
    assert!(symbolic_bare("a-b_c.d!e"));
}

// ── symbolic_alpha_only_opaque_candidate ────────────────────────────────────
// len>=18, no '://', every byte graphic and not a quote, NO digits, has upper +
// lower, punctuation>=3, alpha*2>=len, AND reads as a random token.

/// 18 chars, no digits, 3 '-', upper X + lowercase, improbable letter runs.
const SYM_ALPHA_OK: &str = "Xzqk-pvbg-wmjz-rql";

#[test]
fn symbolic_alpha_positive_precondition_is_random() {
    assert!(is_random_token(SYM_ALPHA_OK));
}

#[test]
fn symbolic_alpha_positive() {
    assert!(symbolic_alpha_only_opaque(SYM_ALPHA_OK));
}

#[test]
fn symbolic_alpha_len_17_too_short_fails() {
    assert!(!symbolic_alpha_only_opaque("Xzqk-pvbg-wmjz-rq"));
}

#[test]
fn symbolic_alpha_with_digit_fails() {
    assert!(!symbolic_alpha_only_opaque("Xzqk-pvbg-wmjz-rq1"));
}

#[test]
fn symbolic_alpha_with_quote_fails() {
    assert!(!symbolic_alpha_only_opaque("Xzqk-pvbg-wmjz-rq`"));
}

#[test]
fn symbolic_alpha_too_few_punctuation_fails() {
    // Only two '-' ⇒ punctuation count 2 < 3.
    assert!(!symbolic_alpha_only_opaque("Xzqkpvbg-wmjz-rqlx"));
}

#[test]
fn symbolic_alpha_without_uppercase_fails() {
    assert!(!symbolic_alpha_only_opaque("xzqk-pvbg-wmjz-rql"));
}

#[test]
fn symbolic_alpha_without_lowercase_fails() {
    assert!(!symbolic_alpha_only_opaque("XZQK-PVBG-WMJZ-RQL"));
}

#[test]
fn symbolic_alpha_dictionary_word_is_not_random_fails() {
    // Pronounceable English ⇒ the random-token gate rejects it.
    let word = "Inter-nal-Conf-data";
    assert!(!is_random_token(word));
    assert!(!symbolic_alpha_only_opaque(word));
}
