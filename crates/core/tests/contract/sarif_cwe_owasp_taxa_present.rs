use keyhog_core::{
    MatchLocation, Reporter, SarifReporter, Severity, VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

fn synthetic_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "test-detector".into(),
        detector_name: "Test Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("****redacted"),
        credential_hash: [0; 32],
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
fn sarif_output_carries_cwe_and_owasp_taxa() {
    let mut buf = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        r.report(&synthetic_finding()).expect("report");
        r.finish().expect("finish");
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid JSON");
    assert_eq!(
        json["runs"][0]["results"][0]["properties"]["cwe"].as_str(),
        Some("CWE-798")
    );
    assert_eq!(
        json["runs"][0]["results"][0]["properties"]["owasp"].as_str(),
        Some("A07:2021")
    );
    assert_eq!(
        json["runs"][0]["taxonomies"][0]["name"].as_str(),
        Some("CWE")
    );
}
