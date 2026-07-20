//! These tests cover the three isolated-bare candidate shape gates in
//! `entropy/isolated.rs`. The owning detector TOML defines each threshold.
//! The scanner compiles those values before it admits a bare token.
//!
//! `symbolic_alpha_only_opaque` depends on the random-vs-dictionary token check;
//! tests that hinge on it self-validate the precondition via `is_random_token`
//! so a model change fails loudly here, not silently in the gate.

use keyhog_scanner::testing::entropy_isolated::{
    colon_separated_opaque, is_random_token, symbolic_alpha_only_opaque,
    symbolic_alpha_only_opaque_with_policy, symbolic_bare, symbolic_bare_with_policy,
};

fn plausibility_policy() -> keyhog_core::DetectorPlausibilityPolicySpec {
    keyhog_core::detector_spec_by_id("generic-keyword-secret")
        .expect("embedded generic-keyword-secret detector must load")
        .plausibility
        .expect("embedded generic-keyword-secret must own plausibility policy")
}

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
// No '://', no ':' or ',', every byte ASCII-graphic and not a quote. Symbol
// count and underscore policy come from the owning detector TOML.

#[test]
fn symbolic_bare_positive() {
    assert!(symbolic_bare("abc-def_ghi"));
}

#[test]
fn symbolic_bare_exactly_two_symbols() {
    assert!(symbolic_bare("ab-cd_ef"));
}

#[test]
fn symbolic_bare_two_underscores_fail_detector_non_underscore_policy() {
    assert!(!symbolic_bare("ab_cd_ef"));
}

#[test]
fn symbolic_bare_symbol_count_follows_detector_policy() {
    let candidate = "ab-cd_ef";
    assert!(symbolic_bare(candidate));
    assert!(!symbolic_bare_with_policy(
        candidate,
        keyhog_core::DetectorPlausibilityPolicySpec {
            isolated_symbolic_min_symbols: 3,
            ..plausibility_policy()
        },
    ));
}

#[test]
fn symbolic_bare_underscore_rule_follows_detector_policy() {
    let candidate = "ab_cd_ef";
    assert!(!symbolic_bare(candidate));
    assert!(symbolic_bare_with_policy(
        candidate,
        keyhog_core::DetectorPlausibilityPolicySpec {
            isolated_symbolic_requires_non_underscore: false,
            ..plausibility_policy()
        },
    ));
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
// The detector policy owns minimum length, symbol count, and alphabetic ratio.
// The shape also requires mixed case, no digits, graphic unquoted bytes, and a
// random-token result.

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
fn symbolic_alpha_symbol_count_follows_detector_policy() {
    assert!(symbolic_alpha_only_opaque(SYM_ALPHA_OK));
    assert!(!symbolic_alpha_only_opaque_with_policy(
        SYM_ALPHA_OK,
        keyhog_core::DetectorPlausibilityPolicySpec {
            isolated_alpha_only_min_symbols: 4,
            ..plausibility_policy()
        },
    ));
}

#[test]
fn symbolic_alpha_ratio_follows_detector_policy() {
    assert!(symbolic_alpha_only_opaque(SYM_ALPHA_OK));
    assert!(!symbolic_alpha_only_opaque_with_policy(
        SYM_ALPHA_OK,
        keyhog_core::DetectorPlausibilityPolicySpec {
            isolated_alpha_only_min_alpha_ratio: 0.9,
            ..plausibility_policy()
        },
    ));
}

#[test]
fn symbolic_alpha_length_follows_detector_policy() {
    assert!(!symbolic_alpha_only_opaque_with_policy(
        "Xzqk-pvbg-wmjz-rq",
        keyhog_core::DetectorPlausibilityPolicySpec {
            isolated_symbolic_min_len: 18,
            ..plausibility_policy()
        },
    ));
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
    // This candidate has two punctuation bytes. The detector requires three.
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
    // The random-token gate rejects this pronounceable English phrase.
    let word = "Inter-nal-Conf-data";
    assert!(!is_random_token(word));
    assert!(!symbolic_alpha_only_opaque(word));
}
