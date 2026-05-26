//! Migrated from `src/report/sarif.rs` inline tests.
use keyhog_core::{
    MatchLocation, Reporter, SarifReporter, Severity, VerificationResult, VerifiedFinding,
};
use std::collections::HashMap;
use std::sync::Arc;
fn synthetic_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("test-detector"),
        detector_name: Arc::from("Test Detector"),
        service: Arc::from("test"),
        severity: Severity::High,
        credential_redacted: std::borrow::Cow::Borrowed("****redacted"),
        credential_hash: "abcdefabcdefabcdef".into(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("config.env")),
            line: Some(42),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.9),
    }
}
#[test]
fn empty_run_still_produces_valid_sarif() {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        r.finish().unwrap();
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid JSON");
    assert_eq!(json["version"].as_str(), Some("2.1.0"));
    let results = json["runs"][0]["results"]
        .as_array()
        .expect("results array");
    assert!(results.is_empty());
}
