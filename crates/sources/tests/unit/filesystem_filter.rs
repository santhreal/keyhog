//! Unit tests for the filesystem exclude-rule validators in
//! `crates/sources/src/filesystem/filter.rs`.
//!
//! The oracle is the documented rule-shape contract (lowercase ASCII, no path
//! separators, no control characters, required leading/trailing dots for
//! suffixes/infixes) and the normalization behavior (trim, dedupe, reject empty).

use keyhog_sources::testing::{normalize_rule_list_for_test, validate_rule_value_for_test};

#[test]
fn validate_extension_accepts_plain_lowercase_and_rejects_dot_or_path_separators() {
    assert!(validate_rule_value_for_test("extensions", "exe", "extension").is_ok());
    assert!(validate_rule_value_for_test("extensions", "png", "extension").is_ok());

    assert!(validate_rule_value_for_test("extensions", ".exe", "extension").is_err());
    assert!(validate_rule_value_for_test("extensions", "a/b", "extension").is_err());
    assert!(validate_rule_value_for_test("extensions", "a\\b", "extension").is_err());
    assert!(validate_rule_value_for_test("extensions", "PNG", "extension").is_err());
}

#[test]
fn validate_path_segment_and_filename_reject_path_separators_and_control_chars() {
    for kind in ["path_segment", "filename"] {
        assert!(validate_rule_value_for_test("dirs", "target", kind).is_ok());
        assert!(validate_rule_value_for_test("dirs", "node_modules", kind).is_ok());
        assert!(validate_rule_value_for_test("dirs", "a/b", kind).is_err());
        assert!(validate_rule_value_for_test("dirs", "a\\b", kind).is_err());
        assert!(validate_rule_value_for_test("dirs", "bad\0dir", kind).is_err());
    }
}

#[test]
fn validate_suffix_requires_leading_dot_and_no_path_separators() {
    assert!(validate_rule_value_for_test("suffixes", ".min", "suffix").is_ok());
    assert!(validate_rule_value_for_test("suffixes", ".bundle", "suffix").is_ok());

    assert!(validate_rule_value_for_test("suffixes", "min", "suffix").is_err());
    assert!(validate_rule_value_for_test("suffixes", ".a/b", "suffix").is_err());
}

#[test]
fn validate_infix_requires_leading_and_trailing_dot_and_no_path_separators() {
    assert!(validate_rule_value_for_test("infixes", ".chunk.", "infix").is_ok());
    assert!(validate_rule_value_for_test("infixes", "chunk", "infix").is_err());
    assert!(validate_rule_value_for_test("infixes", ".chunk", "infix").is_err());
    assert!(validate_rule_value_for_test("infixes", "chunk.", "infix").is_err());
    assert!(validate_rule_value_for_test("infixes", ".a/b.", "infix").is_err());
}

#[test]
fn validate_rule_value_rejects_empty_whitespace_uppercase_and_control_chars() {
    assert!(validate_rule_value_for_test("extensions", "", "extension").is_err());
    assert!(validate_rule_value_for_test("extensions", "   ", "extension").is_err());
    assert!(validate_rule_value_for_test("extensions", "PNG", "extension").is_err());
    assert!(validate_rule_value_for_test("extensions", "pi\ng", "extension").is_err());
}

#[test]
fn normalize_rule_list_trims_validates_and_dedupes() {
    let normalized = normalize_rule_list_for_test(
        "extensions",
        vec![" exe ".into(), "png".into(), "jpg".into()],
        "extension",
    )
    .expect("valid list normalizes");
    assert_eq!(normalized, vec!["exe", "png", "jpg"]);
}

#[test]
fn normalize_rule_list_rejects_uppercase_after_trim() {
    let err = normalize_rule_list_for_test(
        "extensions",
        vec![" exe ".into(), "EXE ".into()],
        "extension",
    )
    .expect_err("uppercase entry must be rejected");
    assert!(err.contains("must be lowercase ASCII"));
}

#[test]
fn normalize_rule_list_rejects_empty_input() {
    let err = normalize_rule_list_for_test("extensions", vec![], "extension")
        .expect_err("empty list must be rejected");
    assert!(err.contains("must contain at least one entry"));
}

#[test]
fn normalize_rule_list_rejects_duplicates() {
    let err =
        normalize_rule_list_for_test("extensions", vec!["png".into(), "png".into()], "extension")
            .expect_err("duplicate entries must be rejected");
    assert!(err.contains("duplicate"));
}

#[test]
fn normalize_rule_list_rejects_invalid_member() {
    let err = normalize_rule_list_for_test("extensions", vec![".png".into()], "extension")
        .expect_err("invalid entry must be rejected");
    assert!(err.contains("extension without dot"));
}
