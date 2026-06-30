//! Boundary contract for the keyword-free ("isolated bare") high-entropy recall
//! floors in `entropy/isolated.rs`. These rescue a high-entropy token that
//! carries NO surrounding secret keyword, so each has a carefully-tuned entropy
//! + shape threshold. They had no direct tests — a future edit to a threshold or
//! a required char-class would silently change recall. These tests pin every
//! boundary so such a change fails loudly.
//!
//! `entropy` is a parameter, so each test controls it exactly and exercises the
//! shape predicate independently of the real Shannon value.

use keyhog_scanner::testing::entropy_isolated::{
    lower_dash_app_password_floor_met, mixed_separator_token_floor_met,
};

// ── mixed_separator_token_floor_met ─────────────────────────────────────────
// Contract: entropy >= 3.65, len >= 20, contains '_', every non-'_' byte is
// ASCII-alphanumeric, and the token carries upper + lower + digit.

/// 20 chars, has '_', upper (A,C,E,G,I), lower (b,d,…), digit (1–5).
const MIXED_OK: &str = "Ab1_Cd2_Ef3_Gh4_Ij5x";

#[test]
fn mixed_separator_positive_well_above_threshold() {
    assert!(mixed_separator_token_floor_met(MIXED_OK, 4.0));
}

#[test]
fn mixed_separator_entropy_exactly_at_threshold_passes() {
    assert!(mixed_separator_token_floor_met(MIXED_OK, 3.65));
}

#[test]
fn mixed_separator_entropy_just_below_threshold_fails() {
    assert!(!mixed_separator_token_floor_met(MIXED_OK, 3.649));
}

#[test]
fn mixed_separator_length_19_below_minimum_fails() {
    // Drop the trailing char -> 19 chars, otherwise valid shape.
    assert!(!mixed_separator_token_floor_met("Ab1_Cd2_Ef3_Gh4_Ij5", 4.0));
}

#[test]
fn mixed_separator_without_underscore_fails() {
    assert!(!mixed_separator_token_floor_met(
        "Ab1Cd2Ef3Gh4Ij5xYz67",
        4.0
    ));
}

#[test]
fn mixed_separator_missing_uppercase_fails() {
    assert!(!mixed_separator_token_floor_met(
        "ab1_cd2_ef3_gh4_ij5x",
        4.0
    ));
}

#[test]
fn mixed_separator_missing_lowercase_fails() {
    assert!(!mixed_separator_token_floor_met(
        "AB1_CD2_EF3_GH4_IJ5X",
        4.0
    ));
}

#[test]
fn mixed_separator_missing_digit_fails() {
    assert!(!mixed_separator_token_floor_met(
        "Abc_Cde_Efg_Ghi_Ijkx",
        4.0
    ));
}

#[test]
fn mixed_separator_non_alphanumeric_char_fails() {
    // The trailing '!' is neither '_' nor alphanumeric.
    assert!(!mixed_separator_token_floor_met(
        "Ab1_Cd2_Ef3_Gh4_Ij5!",
        4.0
    ));
}

// ── lower_dash_app_password_floor_met ───────────────────────────────────────
// Contract: entropy >= 3.9, len == 19, four '-'-separated groups of 4
// lowercase/digit chars (each with a letter AND a digit), and at least one
// non-hex letter (g–z) so a pure-hex UUID-ish token does not qualify.

/// 4x4 groups, each lowercase+digit; w/x/y/z supply the required non-hex letter.
const DASH_OK: &str = "w1xy-z2a3-b4c5-d6e7";

#[test]
fn lower_dash_positive_well_above_threshold() {
    assert!(lower_dash_app_password_floor_met(DASH_OK, 4.0));
}

#[test]
fn lower_dash_entropy_exactly_at_threshold_passes() {
    assert!(lower_dash_app_password_floor_met(DASH_OK, 3.9));
}

#[test]
fn lower_dash_entropy_just_below_threshold_fails() {
    assert!(!lower_dash_app_password_floor_met(DASH_OK, 3.89));
}

#[test]
fn lower_dash_length_not_19_fails() {
    assert!(!lower_dash_app_password_floor_met(
        "w1xy-z2a3-b4c5-d6e78",
        4.0
    ));
}

#[test]
fn lower_dash_group_not_four_chars_fails() {
    // 19 chars but groups are 5/3/4/4.
    assert!(!lower_dash_app_password_floor_met(
        "w1xyz-2a3-b4c5-d6e7",
        4.0
    ));
}

#[test]
fn lower_dash_uppercase_in_group_fails() {
    assert!(!lower_dash_app_password_floor_met(
        "W1xy-z2a3-b4c5-d6e7",
        4.0
    ));
}

#[test]
fn lower_dash_group_missing_digit_fails() {
    // First group "wxyz" has no digit.
    assert!(!lower_dash_app_password_floor_met(
        "wxyz-z2a3-b4c5-d6e7",
        4.0
    ));
}

#[test]
fn lower_dash_group_missing_alpha_fails() {
    // First group "1234" has no letter.
    assert!(!lower_dash_app_password_floor_met(
        "1234-z2a3-b4c5-d6e7",
        4.0
    ));
}

#[test]
fn lower_dash_symbol_in_group_fails() {
    // Trailing '!' is neither lowercase nor digit.
    assert!(!lower_dash_app_password_floor_met(
        "w1xy-z2a3-b4c5-d6e!",
        4.0
    ));
}

#[test]
fn lower_dash_all_hex_no_non_hex_letter_fails() {
    // Every letter is a hex digit (a–f) -> no non-hex letter -> rejected.
    assert!(!lower_dash_app_password_floor_met(
        "a1b2-c3d4-e5f6-a7b8",
        4.0
    ));
}

#[test]
fn lower_dash_single_non_hex_letter_qualifies() {
    // Identical to the all-hex case except one 'g' (non-hex) -> qualifies.
    assert!(lower_dash_app_password_floor_met(
        "a1b2-c3d4-e5f6-g7a8",
        4.0
    ));
}
