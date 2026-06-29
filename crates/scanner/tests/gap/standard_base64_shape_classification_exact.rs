//! Gap test: `standard_base64_shape` (decode/base64.rs).
//!
//! Existing coverage only source-shape-gates this fn (file_gate string match,
//! decode_base64_classifier_hot_path_shape body grep) — its RETURN VALUES were
//! untested. It is the single source of truth for the standard-base64 shape used
//! by `looks_like_uniform_base64_blob` / `is_byte_distribution_base64_blob`, so
//! a drift in the alphabet/padding/remainder rules silently changes those gates.
//! Tuple order: (has_padding, length_multiple_of_four, has_plus, has_slash,
//! distinct_alnum). Verdicts hand-traced against scan_base64_candidate.

use keyhog_scanner::testing::standard_base64_shape_for_test as shape;

#[test]
fn plain_alnum_quad_has_no_padding_or_punct() {
    // A,B,C,D distinct = 4; len 4 -> multiple of four; no +/ no padding.
    assert_eq!(shape("ABCD"), Some((false, true, false, false, 4)));
    // repeated bytes are de-duplicated: A,B distinct = 2.
    assert_eq!(shape("AAAB"), Some((false, true, false, false, 2)));
}

#[test]
fn both_standard_punctuation_marks_are_recorded() {
    // '+' and '/' set has_plus/has_slash; A,B distinct = 2; len 4.
    assert_eq!(shape("AB+/"), Some((false, true, true, true, 2)));
}

#[test]
fn padding_is_recorded_and_keeps_multiple_of_four() {
    // two '=' -> has_padding; A,B distinct = 2; len 4.
    assert_eq!(shape("AB=="), Some((true, true, false, false, 2)));
    // six alnum + two '=' = len 8; A..F distinct = 6.
    assert_eq!(shape("ABCDEF=="), Some((true, true, false, false, 6)));
}

#[test]
fn url_safe_alphabet_is_rejected() {
    // '-'/'_' make it url-safe; standard shape refuses url-safe.
    assert_eq!(shape("AB-_"), None);
    // mixing standard '+' with url-safe '-'/'_' -> mixed alphabet -> None.
    assert_eq!(shape("A+_-"), None);
}

#[test]
fn invalid_length_and_padding_positions_are_rejected() {
    // unpadded length remainder 1 is never valid base64.
    assert_eq!(shape("ABCDE"), None);
    // data byte after padding.
    assert_eq!(shape("AB=C"), None);
    // leading '=' .
    assert_eq!(shape("=ABC"), None);
    // padded but total length not a multiple of four (remainder 2).
    assert_eq!(shape("ABCDE="), None);
}
