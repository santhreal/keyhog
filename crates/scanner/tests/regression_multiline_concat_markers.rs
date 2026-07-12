//! Migrated from the inline `tests` module in `multiline/config.rs` (removed to
//! satisfy `multiline_config_no_inline_tests`). Pins the concatenation-marker
//! recognition and both-scan indicator routing through the `crate::testing`
//! facade. Gated on the `multiline` feature (the predicates are too).
#![cfg(feature = "multiline")]

use keyhog_scanner::testing::{
    multiline_has_concatenation_indicators_for_test as has_concatenation_indicators,
    multiline_has_function_concat_marker_for_test as has_function_concat_marker,
};

#[test]
fn function_concat_marker_matches_all_three_forms_only() {
    // Every form the single-owner marker set must recognize.
    assert!(has_function_concat_marker("x = paste0(\"a\", \"b\")"));
    assert!(has_function_concat_marker("x <- paste(\"a\", \"b\")"));
    assert!(has_function_concat_marker("let x = concat!(\"a\", \"b\");"));
    // Near-misses that must NOT trip it: a different macro, and an identifier
    // that merely embeds "paste" without the call paren.
    assert!(!has_function_concat_marker("let x = format!(\"a\")"));
    assert!(!has_function_concat_marker("let pastexyz = 3"));
    assert!(!has_function_concat_marker("let x = 3.14"));
}

#[test]
fn has_indicators_uses_function_concat_marker_at_both_scans() {
    // paste0 line: whole-text scan and per-line scan both route through the
    // shared marker and flag it as a concatenation indicator.
    assert!(has_concatenation_indicators(
        "token = paste0(\"gh\", \"p_deadbeefdeadbeef\")"
    ));
    // JSON-shaped body is rejected up front regardless of markers.
    assert!(!has_concatenation_indicators("{\"a\": \"b\"}"));
    // Plain assignment with no concat shape is not an indicator.
    assert!(!has_concatenation_indicators("token = \"static_value\""));
}
