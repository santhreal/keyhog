//! Boundary contract for `mixed_contiguous_token_floor_met`: the third
//! keyword-free ("isolated bare") high-entropy recall floor in
//! `entropy/isolated.rs`, and the only one with no separator structure to lean
//! on. It compensates with two extra gates the separator floors omit: the token
//! must NOT be all-hex, and it must read as a RANDOM secret (improbable English
//! bigrams) rather than a pronounceable identifier. It had zero direct tests, so
//! a future edit to its threshold, its `!all_hex` guard, or the randomness gate
//! would silently move recall.
//!
//! `entropy` is a parameter, so each test controls it exactly. The randomness
//! gate depends on an English-bigram model; tests that hinge on it self-validate
//! the precondition via [`is_random_token`] so a model change fails loudly here
//! rather than silently passing the floor test for the wrong reason.

use keyhog_scanner::testing::entropy_isolated::{
    is_random_token, mixed_contiguous_token_floor_met,
};

/// 20 chars, all alphanumeric, upper (P) + lower + digit (1–4), non-hex letters
/// (p,x,i,z,t,v,q,k,g,w,j) so it is not all-hex, and an improbable-bigram run
/// (`pxidztpvqkbgxwjz`) so it reads as random. The single canonical positive.
const CONTIGUOUS_OK: &str = "Pxidztpvqkbgxwjz1234";

/// A second positive whose letter runs are broken by interior digits, proving a
/// digit-fragmented token still clears the randomness gate.
const CONTIGUOUS_OK_SPLIT: &str = "Xz7qkpvbg3wmjzqxhb4j";

/// 22 chars, all alphanumeric, upper + lower + digit, non-hex, but a
/// pronounceable English compound, so the randomness gate rejects it.
const DICTIONARY_22: &str = "Configurationmanager12";

// ── self-validating preconditions ───────────────────────────────────────────

#[test]
fn positive_candidate_precondition_is_random() {
    assert!(is_random_token(CONTIGUOUS_OK));
}

#[test]
fn digit_split_positive_candidate_precondition_is_random() {
    assert!(is_random_token(CONTIGUOUS_OK_SPLIT));
}

#[test]
fn dictionary_candidate_precondition_is_not_random() {
    assert!(!is_random_token(DICTIONARY_22));
}

// ── entropy threshold ───────────────────────────────────────────────────────

#[test]
fn positive_random_token_well_above_threshold() {
    assert!(mixed_contiguous_token_floor_met(CONTIGUOUS_OK, 4.0));
}

#[test]
fn entropy_exactly_at_threshold_passes() {
    assert!(mixed_contiguous_token_floor_met(CONTIGUOUS_OK, 3.65));
}

#[test]
fn entropy_just_below_threshold_fails() {
    assert!(!mixed_contiguous_token_floor_met(CONTIGUOUS_OK, 3.649));
}

#[test]
fn entropy_far_above_threshold_passes() {
    assert!(mixed_contiguous_token_floor_met(CONTIGUOUS_OK, 5.5));
}

#[test]
fn digit_split_random_token_passes() {
    assert!(mixed_contiguous_token_floor_met(CONTIGUOUS_OK_SPLIT, 4.0));
}

// ── length minimum (>= 20) ──────────────────────────────────────────────────

#[test]
fn length_19_below_minimum_fails() {
    // CONTIGUOUS_OK minus one trailing digit -> 19 chars.
    assert!(!mixed_contiguous_token_floor_met(
        "Pxidztpvqkbgxwjz123",
        4.0
    ));
}

#[test]
fn length_exactly_20_is_accepted() {
    assert_eq!(CONTIGUOUS_OK.len(), 20);
    assert!(mixed_contiguous_token_floor_met(CONTIGUOUS_OK, 4.0));
}

#[test]
fn length_21_random_token_passes() {
    assert!(mixed_contiguous_token_floor_met(
        "Pxidztpvqkbgxwjz12345",
        4.0
    ));
}

// ── character-class gates (short-circuit before the randomness gate) ─────────

#[test]
fn non_alphanumeric_symbol_fails() {
    // Trailing '!' is not alphanumeric.
    assert!(!mixed_contiguous_token_floor_met(
        "Pxidztpvqkbgxwjz123!",
        4.0
    ));
}

#[test]
fn underscore_separator_fails() {
    // Unlike the mixed_separator floor, an interior '_' is non-alphanumeric here
    // and disqualifies the token outright.
    assert!(!mixed_contiguous_token_floor_met(
        "Pxidztpv_kbgxwjz1234",
        4.0
    ));
}

#[test]
fn interior_space_fails() {
    assert!(!mixed_contiguous_token_floor_met(
        "Pxidztpv kbgxwjz1234",
        4.0
    ));
}

#[test]
fn missing_uppercase_fails() {
    assert!(!mixed_contiguous_token_floor_met(
        "pxidztpvqkbgxwjz1234",
        4.0
    ));
}

#[test]
fn missing_lowercase_fails() {
    assert!(!mixed_contiguous_token_floor_met(
        "PXIDZTPVQKBGXWJZ1234",
        4.0
    ));
}

#[test]
fn missing_digit_fails() {
    // 20 alphanumeric chars, upper + lower, non-hex, but no digit.
    assert!(!mixed_contiguous_token_floor_met(
        "Pxidztpvqkbgxwjzqxwj",
        4.0
    ));
}

// ── all-hex gate ────────────────────────────────────────────────────────────

#[test]
fn all_hex_lowercase_with_upper_fails() {
    // Every char is a hex digit -> !all_hex is false even though upper/lower/
    // digit are all present.
    assert!(!mixed_contiguous_token_floor_met(
        "Abcdef0123456789abcd",
        4.0
    ));
}

#[test]
fn all_hex_mixed_case_fails() {
    assert!(!mixed_contiguous_token_floor_met(
        "aBcDeF0123456789aBcD",
        4.0
    ));
}

// ── randomness gate (full token shape, gate decides) ────────────────────────

#[test]
fn pronounceable_dictionary_token_fails() {
    // Passes every shape gate (upper/lower/digit, non-hex, len, alphanumeric)
    // but is pronounceable English -> randomness gate rejects it.
    assert!(!mixed_contiguous_token_floor_met(DICTIONARY_22, 4.0));
}

#[test]
fn low_letter_diversity_pattern_fails() {
    // Only two distinct letters (G/x): improbable bigrams but a repetitive mask,
    // not a random token -> the distinct-letter guard in the randomness gate
    // rejects it.
    let mask = "GxGxGxGxGxGxGxGx12Gx";
    assert!(!is_random_token(mask));
    assert!(!mixed_contiguous_token_floor_met(mask, 4.0));
}
