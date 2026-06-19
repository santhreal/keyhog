//! TOML parsing detects malformed syntax with line/column context.
use keyhog_core::SpecError;

#[test]
fn toml_compat_unclosed_table_bracket_errors() {
    let invalid_toml = r#"
[detector
id = "test"
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Unclosed bracket must be rejected"
    );

    // Verify error includes line information for debugging
    if let Err(SpecError::InvalidToml { source, .. }) = result {
        let msg = source.to_string();
        assert!(
            msg.contains("line") || msg.contains("column") || msg.contains("expected"),
            "TOML parse error must include position context: {}",
            msg
        );
    }
}

#[test]
fn toml_compat_invalid_escape_sequence_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Invalid escape \q"
service = "demo"
severity = "high"
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Invalid escape sequence must be rejected"
    );
}

#[test]
fn toml_compat_duplicate_key_in_table_errors() {
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

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Duplicate key must be rejected"
    );
}

#[test]
fn toml_compat_malformed_array_syntax_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
keywords = ["test"

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Unclosed array must be rejected"
    );
}
