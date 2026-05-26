//! Migrated from `src/rule_filter.rs` inline tests.
use keyhog_core::{MatchLocation, RuleSuppressor, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::Arc;
fn finding(detector: &str, service: &str, sev: Severity, path: &str, hash: &str) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from(service),
        severity: sev,
        credential_redacted: std::borrow::Cow::Borrowed("REDACTED"),
        credential_hash: hash.to_string(),
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
    fn multiple_suppress_combine_with_or() {
        let toml = r#"
[[suppress]]
detector = "aws-access-key"

[[suppress]]
detector = "github-pat"
"#;
        let s = RuleSuppressor::parse(toml).expect("parse");
        assert_eq!(s.len(), 2);
        assert!(s.matches(&finding(
            "aws-access-key",
            "aws",
            Severity::Critical,
            "x",
            "h1"
        )));
        assert!(s.matches(&finding(
            "github-pat",
            "github",
            Severity::Critical,
            "x",
            "h2"
        )));
        assert!(!s.matches(&finding("stripe", "stripe", Severity::Critical, "x", "h3")));
    }
