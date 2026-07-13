//! Gap test: the multiline large-file keyword gate (LARGE_FILE_KEYWORD_GATE_BYTES).
//!
//! `has_concatenation_indicators` decides whether a chunk is worth the multiline
//! concatenation-recovery preprocessing. Below `LARGE_FILE_KEYWORD_GATE_BYTES`
//! (now a named const = 4096) the structural concat scan runs unconditionally;
//! above it the chunk must also carry a secret-related keyword, so a large
//! non-secret blob with incidental concat shape is skipped. Pin that gate: the
//! SAME concat shape is an indicator when short, is gated OFF when padded past
//! 4096 bytes with no keyword, and is back ON when the padded text carries one.
//!
//! The whole module is multiline-feature-gated (the pre-scan only exists there).
#![cfg(feature = "multiline")]

use keyhog_scanner::testing::multiline::has_concatenation_indicators_for_test as has_concat;

/// Explicit `"abc" +` string concatenation split across two lines, a concat
/// indicator (the first line trims to end with `+`).
const CONCAT_SHAPE: &str = "x = \"abc\" +\n    \"def\"\n";

#[test]
fn short_concat_shape_is_an_indicator_without_a_keyword() {
    assert!(CONCAT_SHAPE.len() <= 4096);
    assert!(has_concat(CONCAT_SHAPE));
}

#[test]
fn large_blob_without_a_keyword_is_gated_off() {
    // Same concat shape, padded past 4096 bytes with keyword-free filler ('a'
    // runs contain none of ecret/oken/assword/api_key/redential).
    let padded = format!("{CONCAT_SHAPE}{}\n", "a".repeat(5000));
    assert!(padded.len() > 4096);
    assert!(
        !has_concat(&padded),
        "a >4096-byte blob with no secret keyword must skip multiline preprocessing"
    );
}

#[test]
fn large_blob_with_a_keyword_passes_the_gate() {
    // The assignment name carries `secret` (contains the `ecret` keyword), so
    // the same padded length is preprocessed again.
    let with_keyword = format!("secret = \"abc\" +\n    \"def\"\n{}\n", "a".repeat(5000));
    assert!(with_keyword.len() > 4096);
    assert!(has_concat(&with_keyword));
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one text per branch; these SWEEP the gate. The SAME concat
// shape (a split string literal whose first line trims to end with `+`) is: an
// indicator when short (< the 4096-byte gate, no keyword needed); gated OFF when
// padded past the gate with keyword-free filler; and back ON when the padded text
// carries a secret keyword. Digit-only fragments and digit filler GUARANTEE the
// keyword-free cases carry none of `ecret`/`oken`/`assword`/`api_key`/`redential`.
// Traced against `has_concatenation_indicators`. No proptest before.

use proptest::prelude::*;

/// Var-name carriers whose substrings hit the gate's keyword set.
const KEYWORDS: &[&str] = &["secret", "token", "password", "api_key", "credential"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1_500))]

    /// A short concat shape (well under the 4096-byte gate) is an indicator with no
    /// keyword (the structural scan runs unconditionally below the gate).
    #[test]
    fn short_concat_shape_is_an_indicator(a in "[0-9]{1,8}", b in "[0-9]{1,8}") {
        let text = format!("x = \"{a}\" +\n    \"{b}\"\n");
        prop_assert!(text.len() <= 4096);
        prop_assert!(has_concat(&text));
    }

    /// The same shape padded past the gate with keyword-free filler is gated OFF
    /// a large non-secret blob with incidental concat shape is skipped.
    #[test]
    fn large_keyword_free_blob_is_gated_off(
        a in "[0-9]{1,8}",
        b in "[0-9]{1,8}",
        pad in 5000usize..6000,
    ) {
        let text = format!("x = \"{a}\" +\n    \"{b}\"\n{}\n", "1".repeat(pad));
        prop_assert!(text.len() > 4096);
        prop_assert!(!has_concat(&text));
    }

    /// The same padded length WITH a secret keyword (carried by the assignment name)
    /// passes the gate again.
    #[test]
    fn large_blob_with_keyword_passes(
        a in "[0-9]{1,8}",
        b in "[0-9]{1,8}",
        pad in 5000usize..6000,
        ki in 0usize..KEYWORDS.len(),
    ) {
        let kw = KEYWORDS[ki];
        let text = format!("{kw} = \"{a}\" +\n    \"{b}\"\n{}\n", "1".repeat(pad));
        prop_assert!(text.len() > 4096);
        prop_assert!(has_concat(&text));
    }
}
