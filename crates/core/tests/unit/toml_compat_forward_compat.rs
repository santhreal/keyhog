//! Forward compatibility: unknown fields in TOML are rejected to prevent silent siloing.
use keyhog_core::{load_detectors_from_str, SpecError};

#[test]
fn toml_compat_unknown_detector_field_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
keywords = ["test"]
future_field = "should_not_exist"

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = load_detectors_from_str(invalid_toml);
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Unknown detector field must be rejected (forward-compat gate)"
    );

    if let Err(SpecError::InvalidToml { source, .. }) = result {
        let msg = source.to_string();
        assert!(
            msg.contains("future_field") || msg.contains("unknown"),
            "Error must name the unknown field: {}",
            msg
        );
    }
}

#[test]
fn toml_compat_unknown_pattern_field_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
future_feature = true
"#;

    let result = load_detectors_from_str(invalid_toml);
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Unknown pattern field must be rejected"
    );

    if let Err(SpecError::InvalidToml { source, .. }) = result {
        let msg = source.to_string();
        assert!(
            msg.contains("future_feature") || msg.contains("unknown"),
            "Must name the unknown field: {}",
            msg
        );
    }
}

#[test]
fn toml_compat_unknown_verify_field_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"

[detector.verify]
url = "https://api.example.com/verify"
future_field = "upcoming"
method = "POST"

[detector.verify.success]
status = 200
"#;

    let result = load_detectors_from_str(invalid_toml);
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Unknown verify field must be rejected"
    );
}

#[test]
fn toml_compat_unknown_companion_field_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"

[[detector.companions]]
name = "secret_key"
regex = "[A-Za-z0-9]{32}"
within_lines = 5
future_companion_field = "not_allowed"
"#;

    let result = load_detectors_from_str(invalid_toml);
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Unknown companion field must be rejected"
    );
}
