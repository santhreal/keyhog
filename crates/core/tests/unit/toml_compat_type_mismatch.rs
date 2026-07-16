//! TOML type mismatches are rejected with clear error messages.
use keyhog_core::SpecError;

#[test]
fn toml_compat_keywords_as_string_instead_of_array_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = "should_be_array"

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "String keywords must be rejected (should be array)"
    );

    if let Err(SpecError::InvalidToml { source, .. }) = result {
        let msg = source.to_string();
        assert!(
            msg.contains("array") || msg.contains("type") || msg.contains("keywords"),
            "Type mismatch error must indicate the problem: {}",
            msg
        );
    }
}

#[test]
fn toml_compat_severity_as_integer_instead_of_string_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = 42
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
        "Integer severity must be rejected"
    );
}

#[test]
fn toml_compat_patterns_as_single_table_instead_of_array_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["test"]

[detector.patterns]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Single [detector.patterns] table must be rejected (should be [[detector.patterns]] array)"
    );
}

#[test]
fn toml_compat_pattern_group_as_string_instead_of_integer_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["test"]

[[detector.patterns]]
regex = "test_(.*)"
group = "should_be_int"
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "String group must be rejected (should be integer)"
    );
}
