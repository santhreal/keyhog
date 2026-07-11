#![cfg(feature = "multiline")]

use keyhog_scanner::testing::{
    multiline_has_concatenation_indicators_for_test as has_concatenation_indicators,
    multiline_has_function_concat_marker_for_test as has_function_concat_marker,
};

#[test]
fn function_concat_marker_matches_all_three_forms_only() {
    assert!(has_function_concat_marker("x = paste0(\"a\", \"b\")"));
    assert!(has_function_concat_marker("x <- paste(\"a\", \"b\")"));
    assert!(has_function_concat_marker("let x = concat!(\"a\", \"b\");"));
    assert!(!has_function_concat_marker("let x = format!(\"a\")"));
    assert!(!has_function_concat_marker("let pastexyz = 3"));
    assert!(!has_function_concat_marker("let x = 3.14"));
}

#[test]
fn indicator_admission_uses_function_concat_markers() {
    assert!(has_concatenation_indicators(
        "token = paste0(\"gh\", \"p_deadbeefdeadbeef\")",
    ));
    assert!(!has_concatenation_indicators("{\"a\": \"b\"}"));
    assert!(!has_concatenation_indicators("token = \"static_value\""));
}
