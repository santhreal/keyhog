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
fn detector_match_only() {
    let toml = r#"
[[suppress]]
detector = "aws-access-key"
"#;
    let s = RuleSuppressor::parse(toml).expect("parse");
    let aws = finding("aws-access-key", "aws", Severity::Critical, "x.rs", "h1");
    let github = finding("github-pat", "github", Severity::Critical, "x.rs", "h2");
    assert!(s.matches(&aws));
    assert!(!s.matches(&github));
}
