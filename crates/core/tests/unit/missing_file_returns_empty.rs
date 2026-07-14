//! Migrated from `src/rule_filter.rs` inline tests.
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
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
        credential_hash: {
            let mut bytes = [0u8; 32];
            let hash = hash.as_bytes();
            let len = hash.len().min(bytes.len());
            bytes[..len].copy_from_slice(&hash[..len]);
            bytes.into()
        },
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
        confidence: Some(0.9),
    }
}
#[test]
fn missing_file_returns_empty() {
    let path = std::path::PathBuf::from("/nonexistent/.keyhogignore.toml");
    let s = keyhog_core::testing::CoreTestApi::rule_suppressor_load(
        &keyhog_core::testing::TestApi,
        &path,
    )
    .expect("load");
    assert!(!s.matches(&finding(
        "aws-access-key",
        "aws",
        Severity::Critical,
        "x",
        "h1"
    )));
}
