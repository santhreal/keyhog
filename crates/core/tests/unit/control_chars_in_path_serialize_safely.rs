//! Control characters in paths must JSON-escape safely.

use keyhog_core::{
    MatchLocation, Severity, VerificationResult, VerifiedFinding,
};
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
        credential_hash: "deadbeef".into(),
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
fn control_chars_in_path_serialize_safely() {
    let finding = finding_with_hostile_path("path\r\nwith\x1b[31mANSI\x1bcontrol\tchars");
    let json = serde_json::to_string(&finding).unwrap();
    assert!(json.contains("\\r"));
    assert!(json.contains("\\n"));
    assert!(json.contains("\\t"));
    assert!(json.contains("\\u001b"));
    let _: serde_json::Value = serde_json::from_str(&json).unwrap();
}
