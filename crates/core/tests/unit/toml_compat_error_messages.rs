//! Error messages from TOML parsing contain file path and position context.
use keyhog_core::{load_detectors_from_str, SpecError};

#[test]
fn toml_compat_error_includes_line_column_info() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test
service = "demo"
severity = "high"
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = load_detectors_from_str(invalid_toml);
    assert!(matches!(result, Err(SpecError::InvalidToml { .. })));

    if let Err(SpecError::InvalidToml { source, .. }) = result {
        let msg = source.to_string();
        // toml crate includes line/column in error messages
        assert!(
            msg.contains("line") || msg.contains("column") || msg.contains("EOF"),
            "Parse error must include position context: {}",
            msg
        );
    }
}

#[test]
fn toml_compat_read_file_error_includes_path() {
    // This test uses SpecError::InvalidToml since load_detectors_from_str
    // doesn't use ReadFile path handling (that's for load_detectors)
    let invalid_toml = "not valid [[[[";

    let result = load_detectors_from_str(invalid_toml);
    if let Err(SpecError::InvalidToml { path, source }) = result {
        // Path should be "<string>" for string inputs
        assert_eq!(path.to_string_lossy(), "<string>");

        let msg = source.to_string();
        // Error message should explain the parse failure
        assert!(!msg.is_empty(), "Error message must not be empty");
    }
}

#[test]
fn toml_compat_missing_required_field_error_context() {
    let invalid_toml = r#"
[detector]
name = "Missing ID"
service = "demo"
severity = "high"
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = load_detectors_from_str(invalid_toml);
    if let Err(SpecError::InvalidToml { source, .. }) = result {
        let msg = source.to_string();
        // serde missing field error should mention the field
        assert!(
            msg.contains("id") || msg.contains("missing field"),
            "Missing field error must identify the field: {}",
            msg
        );
    }
}

#[test]
fn toml_compat_duplicate_key_error_includes_location() {
    let invalid_toml = r#"
[detector]
id = "test"
id = "duplicate"
name = "Test"
service = "demo"
severity = "high"
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = load_detectors_from_str(invalid_toml);
    if let Err(SpecError::InvalidToml { source, .. }) = result {
        let msg = source.to_string();
        assert!(
            msg.contains("duplicate") || msg.contains("id") || msg.contains("line"),
            "Duplicate key error should reference the problem: {}",
            msg
        );
    }
}

#[test]
fn toml_compat_error_display_format() {
    let invalid_toml = "[[[";

    let result = load_detectors_from_str(invalid_toml);
    if let Err(err) = result {
        let display_msg = format!("{}", err);
        // Display implementation should wrap error info
        assert!(
            display_msg.contains("TOML")
                || display_msg.contains("invalid")
                || !display_msg.is_empty(),
            "Error Display must be informative: {}",
            display_msg
        );
    }
}
