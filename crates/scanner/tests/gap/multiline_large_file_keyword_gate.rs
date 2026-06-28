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

/// Explicit `"abc" +` string concatenation split across two lines — a concat
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
