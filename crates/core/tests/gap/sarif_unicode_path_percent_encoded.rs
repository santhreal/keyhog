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
        companions_redacted: std::collections::HashMap::new(),
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
        entropy: None,
        confidence: Some(0.9),
    }
}

#[test]
fn sarif_unicode_path_is_percent_encoded_in_uri() {
    let mut finding = synthetic_finding();
    finding.location.file_path = Some("/tmp/réport.json".into());
    let mut buf = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        r.report(&finding).expect("report");
        r.finish().expect("finish");
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("json");
    let uri = json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
        ["uri"]
        .as_str()
        .expect("uri");
    assert!(
        uri.contains("%C3%A9"),
        "unicode path must be percent-encoded, got {uri}"
    );
}
