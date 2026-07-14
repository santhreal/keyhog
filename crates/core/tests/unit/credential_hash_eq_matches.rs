//! Migrated from `src/rule_filter.rs` inline tests.
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::collections::HashMap;
use std::sync::Arc;
fn finding(
    detector: &str,
    service: &str,
    sev: Severity,
    path: &str,
    hash: [u8; 32],
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from(detector),
        detector_name: Arc::from(detector),
        service: Arc::from(service),
        severity: sev,
        credential_redacted: std::borrow::Cow::Borrowed("REDACTED"),
        credential_hash: hash.into(),
        companions_redacted: std::collections::HashMap::new(),
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
        entropy: None,
        confidence: Some(0.9),
    }
}
#[test]
fn credential_hash_eq_matches() {
    let deadbeef_hash = [0xde; 32];
    let feedface_hash = [0xfe; 32];
    let toml = r#"
[[suppress]]
credential_hash = "dededededededededededededededededededededededededededededededede"
"#;
    let s = keyhog_core::testing::CoreTestApi::rule_suppressor_parse(
        &keyhog_core::testing::TestApi,
        toml,
    )
    .expect("parse");
    assert!(s.matches(&finding("x", "x", Severity::High, "p", deadbeef_hash)));
    assert!(!s.matches(&finding("x", "x", Severity::High, "p", feedface_hash)));
}
