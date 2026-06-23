use crate::support::reporters::SarifReporter;
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::borrow::Cow;
use std::collections::HashMap;

fn synthetic_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "test-detector".into(),
        detector_name: "Test Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("****redacted"),
        credential_hash: [0; 32].into(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("config.env".into()),
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
fn sarif_fix_suggestion_uses_service_env_var_fallback() {
    let mut buf = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        r.report(&synthetic_finding()).expect("report");
        r.finish().expect("finish");
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid JSON");
    let fix = json["runs"][0]["results"][0]["fixes"][0]["artifactChanges"][0]["replacements"][0]
        ["insertedContent"]["text"]
        .as_str();
    assert_eq!(fix, Some("${TEST_KEY}"));
}
