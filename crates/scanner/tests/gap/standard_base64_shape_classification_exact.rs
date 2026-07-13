//! Gap test: `standard_base64_shape` (decode/base64.rs).
//!
//! Existing coverage only source-shape-gates this fn (file_gate string match,
//! decode_base64_classifier_hot_path_shape body grep), its RETURN VALUES were
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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example of each rule; these SWEEP them. The core is a
// UNIVERSAL CONSISTENCY invariant: whenever `shape` admits a candidate, every
// field is pinned to an exact independent computation (no mirror-oracle) 
// `distinct_alnum` equals the count of distinct ASCII-alnum byte VALUES,
// `has_plus`/`has_slash`/`has_padding` mirror the candidate's bytes, and a Some
// result never carries a url-safe byte. Then CONSTRUCTIVE positives (plain quad,
// padded) and negatives (url-safe, foreign byte, remainder-1) lock recall and the
// rejection rules. All traced against decode/base64.rs:132. No proptest before.

use proptest::prelude::*;
use std::collections::BTreeSet;

/// Url-safe bytes that force a `None` (mixed/url-safe alphabet).
const URL_SAFE: &[char] = &['-', '_'];

/// Bytes outside the base64 alphabet entirely (any one aborts the scan).
const FOREIGN: &[char] = &[' ', '*', '#', '.', ',', '!'];

/// The count of distinct ASCII-alphanumeric byte VALUES in `s` (matches the
/// source's `seen_alnum` dedup).
fn distinct_alnum_count(s: &str) -> u32 {
    s.bytes()
        .filter(u8::is_ascii_alphanumeric)
        .collect::<BTreeSet<u8>>()
        .len() as u32
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// Whenever `shape` admits a candidate, every returned field is EXACTLY the
    /// independent computation. Alphabet includes url-safe bytes so the "Some ⇒ no
    /// url-safe" branch is genuinely exercised.
    #[test]
    fn an_admitted_shape_is_field_exact(cand in "[A-Za-z0-9+/=_-]{0,24}") {
        if let Some((has_padding, len_mul4, has_plus, has_slash, distinct)) = shape(&cand) {
            prop_assert!(!cand.contains('-') && !cand.contains('_'), "url-safe admitted: {:?}", cand);
            prop_assert_eq!(len_mul4, cand.len() % 4 == 0);
            prop_assert!(!has_padding || len_mul4, "padded but not mult-of-4: {:?}", cand);
            prop_assert_eq!(has_padding, cand.contains('='));
            prop_assert_eq!(has_plus, cand.contains('+'));
            prop_assert_eq!(has_slash, cand.contains('/'));
            prop_assert_eq!(distinct, distinct_alnum_count(&cand));
        }
    }

    /// No panic on arbitrary Unicode / bytes (non-ASCII aborts the scan cleanly).
    #[test]
    fn never_panics_on_arbitrary_input(cand in "(?s).{0,40}") {
        let _ = shape(&cand);
    }

    /// RECALL: a pure-alnum string whose length is a multiple of four is plain
    /// standard base64 (no padding, no punctuation, distinct-alnum exact).
    #[test]
    fn pure_alnum_multiple_of_four_is_plain_standard(
        quads in prop::collection::vec("[A-Za-z0-9]{4}", 1..6),
    ) {
        let s: String = quads.concat();
        let d = distinct_alnum_count(&s);
        prop_assert_eq!(shape(&s), Some((false, true, false, false, d)));
    }

    /// RECALL: `<alnum·(4k+2)>==` is recorded as padded standard base64.
    #[test]
    fn padded_alnum_is_recorded(
        quads in prop::collection::vec("[A-Za-z0-9]{4}", 0..5),
        two in "[A-Za-z0-9]{2}",
    ) {
        let base = format!("{}{}", quads.concat(), two);
        let d = distinct_alnum_count(&base);
        let s = format!("{base}==");
        prop_assert_eq!(shape(&s), Some((true, true, false, false, d)));
    }

    /// An unpadded length with remainder 1 (mod 4) is never valid base64.
    #[test]
    fn unpadded_remainder_one_is_rejected(
        quads in prop::collection::vec("[A-Za-z0-9]{4}", 0..5),
        one in "[A-Za-z0-9]{1}",
    ) {
        let s = format!("{}{}", quads.concat(), one);
        prop_assert_eq!(shape(&s), None);
    }

    /// A url-safe byte (`-`/`_`) anywhere rejects the standard shape.
    #[test]
    fn url_safe_bytes_are_rejected(
        pre in "[A-Za-z0-9]{0,8}",
        post in "[A-Za-z0-9]{0,8}",
        u in 0usize..URL_SAFE.len(),
    ) {
        let s = format!("{pre}{}{post}", URL_SAFE[u]);
        prop_assert_eq!(shape(&s), None);
    }

    /// A byte outside the base64 alphabet anywhere aborts the scan → `None`.
    #[test]
    fn foreign_bytes_are_rejected(
        pre in "[A-Za-z0-9]{0,8}",
        post in "[A-Za-z0-9]{0,8}",
        f in 0usize..FOREIGN.len(),
    ) {
        let s = format!("{pre}{}{post}", FOREIGN[f]);
        prop_assert_eq!(shape(&s), None);
    }
}
