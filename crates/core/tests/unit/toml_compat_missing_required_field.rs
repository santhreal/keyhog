//! TOML parsing rejects missing required detector fields with context.
use keyhog_core::{load_detectors_from_str, SpecError};

#[test]
fn toml_compat_missing_id_field_errors_with_context() {
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
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Must reject TOML with missing 'id' field"
    );

    // Verify error message mentions the missing field
    if let Err(SpecError::InvalidToml { source, .. }) = result {
        let msg = source.to_string();
        assert!(
            msg.contains("id") || msg.contains("missing"),
            "Error context must mention 'id' field: {}",
            msg
        );
    }
}

#[test]
fn toml_compat_missing_severity_field_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = load_detectors_from_str(invalid_toml);
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Missing severity field must be rejected"
    );
}

#[test]
fn toml_compat_missing_patterns_array_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
keywords = ["test"]
"#;

    let result = load_detectors_from_str(invalid_toml);
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Missing patterns array must be rejected"
    );
}
