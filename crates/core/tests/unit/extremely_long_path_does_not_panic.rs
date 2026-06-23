//! Megabyte-scale path strings must serialize without panic.

use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

fn finding_with_hostile_path(path: &str) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::Medium,
        credential_redacted: Cow::Borrowed("****"),
        credential_hash: [0; 32].into(),
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
        confidence: Some(0.5),
    }
}

#[test]
fn extremely_long_path_does_not_panic() {
    let long = "a".repeat(1024 * 1024);
    let finding = finding_with_hostile_path(&long);
    let json = serde_json::to_string(&finding).unwrap();
    assert!(json.len() > 1024 * 1024);
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        v["location"]["file_path"].as_str().unwrap().len(),
        long.len()
    );
}
