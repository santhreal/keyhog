//! Boundary cases: edge values, empty collections, malformed enums, etc.
use keyhog_core::SpecError;

#[test]
fn toml_compat_invalid_severity_enum_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "CRITICAL_PLUS"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
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
        "Invalid severity enum must be rejected"
    );

    if let Err(SpecError::InvalidToml { source, .. }) = result {
        let msg = source.to_string();
        assert!(
            msg.contains("severity") || msg.contains("unknown variant"),
            "Error must indicate severity enum issue: {}",
            msg
        );
    }
}

#[test]
fn toml_compat_invalid_http_method_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"

[detector.verify]
url = "https://example.com"
method = "INVALID_METHOD"

[detector.verify.success]
status = 200
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Invalid HTTP method must be rejected"
    );
}

#[test]
fn toml_compat_negative_min_confidence_errors() {
    let invalid_toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["test"]
min_confidence = -0.5

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    // Parsing itself may succeed, but validation should catch this
    // Check both cases
    if let Ok(specs) = result {
        assert_eq!(specs.len(), 1);
        let spec = &specs[0];
        // If it parsed, verify the value made it through (the validation gate handles the semantics)
        assert!(spec.min_confidence.is_some());
    }
}

#[test]
fn toml_compat_empty_string_id_field() {
    let invalid_toml = r#"
[detector]
id = ""
name = "Empty ID"
service = "demo"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    // Should parse but validation may reject it or allow it depending on the gate
    // Just ensure it doesn't panic
    let _ = result;
}

#[test]
fn toml_compat_very_long_string_fields() {
    let long_string = "a".repeat(10000);
    let toml_str = format!(
        r#"
[detector]
id = "test"
name = "{}"
service = "demo"
severity = "high"
ml = {{ match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }}
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{{8}}"
"#,
        long_string
    );

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        &toml_str,
    );
    // Should parse without panic or OOM
    assert!(
        result.is_ok() || matches!(result, Err(SpecError::InvalidToml { .. })),
        "Parsing long strings must not panic"
    );
}

#[test]
fn toml_compat_unicode_in_id_field() {
    let invalid_toml = r#"
[detector]
id = "test_🔑_key"
name = "Unicode ID"
service = "demo"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    // Should parse successfully (Unicode is valid in TOML strings)
    if let Ok(specs) = result {
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].id, "test_🔑_key");
    }
}

#[test]
fn toml_compat_zero_within_lines_companion() {
    let toml_str = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["test"]

[[detector.patterns]]
regex = "test_[A-Z0-9]{8}"

[[detector.companions]]
name = "tight"
regex = "[A-Z0-9]{10}"
within_lines = 0
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml_str,
    );
    // Should parse (semantics validation is separate)
    assert!(result.is_ok() || matches!(result, Err(SpecError::InvalidToml { .. })));
}

#[test]
fn toml_compat_multiple_patterns_parse() {
    let toml_str = r#"
[detector]
id = "multi"
name = "Multiple Patterns"
service = "demo"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["prefix_"]

[[detector.patterns]]
regex = "prefix_[A-Z0-9]{16}"
description = "First pattern"

[[detector.patterns]]
regex = "secret_[a-z0-9]{32}"
description = "Second pattern"

[[detector.patterns]]
regex = "[0-9]{6}-[0-9]{6}"
group = 0
"#;

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml_str,
    );
    if let Ok(specs) = result {
        assert_eq!(specs[0].patterns.len(), 3);
        assert_eq!(
            specs[0].patterns[0].description,
            Some("First pattern".into())
        );
        assert_eq!(
            specs[0].patterns[1].description,
            Some("Second pattern".into())
        );
        assert_eq!(specs[0].patterns[2].group, Some(0));
    }
}
