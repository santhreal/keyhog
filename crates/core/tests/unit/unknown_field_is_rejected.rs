//! Migrated from `src/rule_filter.rs` inline tests.
use keyhog_core::{MatchLocation, RuleSuppressor, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::Arc;
fn finding(
    detector: &str,
    service: &str,
    sev: Severity,
    path: &str,
    hash: &str,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from(service),
        severity: sev,
        credential_redacted: std::borrow::Cow::Borrowed("REDACTED"),
        credential_hash: [0; 32],
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(path)),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Skipped,
        metadata: HashMap::new(),
        additional_locations: Vec::new(),
        confidence: Some(0.9),
    }
}
#[test]
fn unknown_field_is_rejected() {
    let toml = r#"
[[suppress]]
not_a_field = "x"
"#;
    let err = RuleSuppressor::parse(toml).expect_err("must reject");
    let msg = format!("{err}");
    // serde's deny_unknown_fields produces a message naming the
    // bad field; just verify it errors.
    assert!(
        msg.contains("not_a_field") || msg.contains("unknown"),
        "got: {msg}"
    );
}
