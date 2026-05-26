//! Migrated from `src/report/sarif.rs` inline tests.
use keyhog_core::{MatchLocation, SarifReporter, Severity, VerificationResult, VerifiedFinding};
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
    fn sarif_uri_full_run_with_absolute_path() {
        let mut finding = synthetic_finding();
        finding.location.file_path = Some(Arc::from("/etc/keys/aws.env"));
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut r = SarifReporter::new(&mut buf);
            r.report(&finding).unwrap();
            r.finish().unwrap();
        }
        let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid JSON");
        let loc_uri = json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"]
            .as_str();
        assert_eq!(loc_uri, Some("file:///etc/keys/aws.env"));
        let fix_uri = json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]
            ["artifactLocation"]["uri"]
            .as_str();
        assert_eq!(fix_uri, Some("file:///etc/keys/aws.env"));
    }
