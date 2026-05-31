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
fn path_predicates_combine() {
    let toml = r#"
[[suppress]]
path_starts_with = "vendor/"

[[suppress]]
path_ends_with = ".min.js"

[[suppress]]
path_regex = "^docs/[a-z]+\\.md$"
"#;
    let s = RuleSuppressor::parse(toml).expect("parse");
    let v = |p: &str| finding("any", "any", Severity::High, p, "h");
    assert!(s.matches(&v("vendor/lib/foo.rs")));
    assert!(s.matches(&v("dist/app.min.js")));
    assert!(s.matches(&v("docs/readme.md")));
    assert!(!s.matches(&v("src/main.rs")));
}
