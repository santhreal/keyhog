//! TOML parsing rejects missing required detector fields with context.
use keyhog_core::SpecError;

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

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
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

    let result = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        invalid_toml,
    );
    assert!(
        matches!(result, Err(SpecError::InvalidToml { .. })),
        "Missing severity field must be rejected"
    );
}

#[test]
fn missing_patterns_parses_but_is_rejected_by_the_quality_gate() {
    // Unlike id/name/service/severity (genuinely required, no serde default),
    // `patterns` IS `#[serde(default)]` so a phase2-generic keyword detector can
    // omit it. Omitting patterns therefore PARSES; the recall-safety requirement
    // (a regex detector must carry an anchor) is enforced at validation time by
    // `validate_patterns_present`, not at parse time.
    let toml = r#"
[detector]
id = "test"
name = "Test"
service = "demo"
severity = "high"
keywords = ["test"]
"#;

    let detectors = keyhog_core::testing::CoreTestApi::load_detectors_from_str(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect("omitting patterns must PARSE: patterns is #[serde(default)]");

    let issues = keyhog_core::validate_detector(&detectors[0]);
    assert!(
        issues.iter().any(|i| matches!(
            i,
            keyhog_core::QualityIssue::Error(m) if m.contains("no patterns defined")
        )),
        "a default (regex) kind detector with no patterns must be a 'no patterns defined' \
         quality Error; got {issues:?}"
    );
}
