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
fn detector_and_path_combine_with_and() {
    let toml = r#"
[[suppress]]
detector = "aws-access-key"
path_contains = "/tests/"
"#;
    let s = RuleSuppressor::parse(toml).expect("parse");
    let aws_in_test = finding(
        "aws-access-key",
        "aws",
        Severity::Critical,
        "src/tests/fixtures.rs",
        "h",
    );
    let aws_in_src = finding(
        "aws-access-key",
        "aws",
        Severity::Critical,
        "src/main.rs",
        "h",
    );
    let stripe_in_test = finding(
        "stripe",
        "stripe",
        Severity::Critical,
        "src/tests/fixtures.rs",
        "h",
    );
    assert!(s.matches(&aws_in_test));
    assert!(!s.matches(&aws_in_src));
    assert!(!s.matches(&stripe_in_test));
}
