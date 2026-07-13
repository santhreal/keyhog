//! Boundary contract for `contains_non_padding_equals` (decode/base64.rs), the
//! single base64-padding discriminator now shared by both isolated-bare entropy
//! gates (previously two inline copies in `entropy/isolated.rs` and
//! `entropy/plausibility.rs`). It answers: does the value hold an `=` that is
//! NOT valid trailing base64 padding (at most two trailing `=`)? A non-padding
//! `=` is the signal that an opaque token is really a `key=value` fragment.
//!
//! These tests pin the discriminator so the consolidation can never drift: the
//! padding-count boundary (0/1/2 vs 3+), `=` positions (leading / internal /
//! pre-padding / trailing), and char-boundary safety when a multibyte char
//! precedes the trailing padding run.

use keyhog_scanner::testing::contains_non_padding_equals;

// ── valid padding only ⇒ false ──────────────────────────────────────────────

#[test]
fn empty_string_has_none() {
    assert!(!contains_non_padding_equals(""));
}

#[test]
fn no_equals_at_all_has_none() {
    assert!(!contains_non_padding_equals("abcABC0123"));
}

#[test]
fn one_trailing_pad_is_valid() {
    assert!(!contains_non_padding_equals("Zm9vYmE="));
}

#[test]
fn two_trailing_pad_is_valid() {
    assert!(!contains_non_padding_equals("Zm9vYg=="));
}

#[test]
fn two_equals_only_is_valid_padding() {
    assert!(!contains_non_padding_equals("=="));
}

#[test]
fn one_equals_only_is_valid_padding() {
    assert!(!contains_non_padding_equals("="));
}

#[test]
fn realistic_base64_no_padding_has_none() {
    assert!(!contains_non_padding_equals("QWxhZGRpbjpvcGVu"));
}

#[test]
fn realistic_base64_one_padding_has_none() {
    assert!(!contains_non_padding_equals("QWxhZGRpbjpvcGU="));
}

#[test]
fn multibyte_prefix_before_valid_padding_has_none() {
    // 'é' is two bytes; the prefix slice must land on its char boundary, not
    // panic, and report no non-padding '='.
    assert!(!contains_non_padding_equals("café=="));
}

// ── a non-padding `=` ⇒ true ────────────────────────────────────────────────

#[test]
fn assignment_with_trailing_value() {
    assert!(contains_non_padding_equals("key=value"));
}

#[test]
fn single_internal_equals() {
    assert!(contains_non_padding_equals("a=b"));
}

#[test]
fn leading_equals() {
    assert!(contains_non_padding_equals("=abc"));
}

#[test]
fn three_trailing_equals_exceeds_padding() {
    assert!(contains_non_padding_equals("abc==="));
}

#[test]
fn four_trailing_equals_exceeds_padding() {
    assert!(contains_non_padding_equals("ab===="));
}

#[test]
fn three_equals_only_exceeds_padding() {
    assert!(contains_non_padding_equals("==="));
}

#[test]
fn equals_before_two_char_padding() {
    assert!(contains_non_padding_equals("ab=cd=="));
}

#[test]
fn equals_before_one_char_padding() {
    assert!(contains_non_padding_equals("x=y="));
}

#[test]
fn two_internal_equals_with_trailing_pad() {
    assert!(contains_non_padding_equals("a=b="));
}

#[test]
fn equals_in_token_interior() {
    assert!(contains_non_padding_equals("abcdef=ghij"));
}

#[test]
fn token_then_assignment_separator() {
    assert!(contains_non_padding_equals("TOKEN=abcdef"));
}

#[test]
fn multibyte_prefix_with_assignment_equals() {
    assert!(contains_non_padding_equals("café=v"));
}
