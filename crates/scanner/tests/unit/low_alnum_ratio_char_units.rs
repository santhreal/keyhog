//! These tests cover the detector-owned alphanumeric ratio gate. The gate counts
//! characters on both sides of the ratio, including multibyte letters.

use keyhog_scanner::testing::{
    entropy_has_low_alnum_ratio_for_test as has_low_alnum_ratio,
    entropy_has_low_alnum_ratio_with_policy_for_test as has_low_alnum_ratio_with_policy,
};

// ── ASCII: char count == byte count, behaviour unchanged ────────────────────

#[test]
fn all_alphanumeric_is_not_low() {
    assert!(!has_low_alnum_ratio("abc123XYZ"));
}

#[test]
fn digits_only_is_not_low() {
    assert!(!has_low_alnum_ratio("12345678"));
}

#[test]
fn mixed_case_alnum_is_not_low() {
    assert!(!has_low_alnum_ratio("AbCdEf12"));
}

#[test]
fn all_symbols_is_low() {
    assert!(has_low_alnum_ratio("!@#$%^&*"));
}

#[test]
fn all_dashes_is_low() {
    // '-' is not alphanumeric.
    assert!(has_low_alnum_ratio("--------"));
}

#[test]
fn exactly_half_alnum_is_not_low() {
    // 2 of 4 chars alnum ⇒ ratio 0.5, not strictly below ⇒ not low.
    assert!(!has_low_alnum_ratio("ab!@"));
}

#[test]
fn boundary_follows_detector_ratio() {
    let candidate = "ab!@";
    assert!(!has_low_alnum_ratio(candidate));
    assert!(has_low_alnum_ratio_with_policy(candidate, 0.75));
}

#[test]
fn just_below_half_is_low() {
    // 2 of 5 chars alnum ⇒ 0.4 < 0.5.
    assert!(has_low_alnum_ratio("ab!@#"));
}

#[test]
fn just_above_half_is_not_low() {
    // 3 of 5 chars alnum ⇒ 0.6.
    assert!(!has_low_alnum_ratio("abc!@"));
}

#[test]
fn two_thirds_alnum_is_not_low() {
    // 4 of 6 chars alnum.
    assert!(!has_low_alnum_ratio("ab!cd!"));
}

#[test]
fn single_alnum_char_is_not_low() {
    assert!(!has_low_alnum_ratio("a"));
}

#[test]
fn single_symbol_is_low() {
    assert!(has_low_alnum_ratio("!"));
}

#[test]
fn one_alnum_many_symbols_is_low() {
    assert!(has_low_alnum_ratio("a========"));
}

#[test]
fn whitespace_is_low() {
    assert!(has_low_alnum_ratio(" "));
}

#[test]
fn empty_is_low() {
    // No characters ⇒ none alphanumeric ⇒ low ratio.
    assert!(has_low_alnum_ratio(""));
}

// ── multibyte: char-based counting (the fix) ────────────────────────────────

#[test]
fn accented_letters_are_not_low() {
    // c,a,f,é all alphanumeric ⇒ 4/4 by character count.
    assert!(!has_low_alnum_ratio("café"));
}

#[test]
fn all_cjk_ideographs_are_not_low() {
    // 4 ideographs, each 3 bytes (12 bytes total). By CHARACTER count 4/4 ⇒ not
    // low. The old byte-denominator form computed 4/12 = 0.33 and wrongly
    // flagged this as low (this is the case the fix corrects).
    assert!(!has_low_alnum_ratio("日本語中"));
}

#[test]
fn all_cyrillic_letters_are_not_low() {
    // 6 Cyrillic letters (12 bytes). Char count 6/6 ⇒ not low; byte form 6/12.
    assert!(!has_low_alnum_ratio("Привет"));
}

#[test]
fn multibyte_letter_with_trailing_symbol_is_not_low() {
    // café + '!' ⇒ 4 of 5 chars alnum.
    assert!(!has_low_alnum_ratio("café!"));
}

#[test]
fn multibyte_letter_among_majority_symbols_is_low() {
    // é + four symbols ⇒ 1 of 5 chars alnum, low regardless of counting unit.
    assert!(has_low_alnum_ratio("é!@#$"));
}

#[test]
fn emoji_are_not_alphanumeric_and_are_low() {
    // Emoji are not alphanumeric ⇒ 0 of 4 chars alnum.
    assert!(has_low_alnum_ratio("🔑🔑🔑🔑"));
}
