//! Hostile path metadata must serialize to valid JSON.

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
        confidence: Some(0.5),
    }
}

#[test]
fn nul_bytes_in_path_serialize_to_valid_json() {
    let finding = finding_with_hostile_path("evil\0name.env");
    let json = serde_json::to_string(&finding).unwrap();
    assert!(json.contains("\\u0000"), "NUL must be escaped in JSON");
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.is_object());
}
