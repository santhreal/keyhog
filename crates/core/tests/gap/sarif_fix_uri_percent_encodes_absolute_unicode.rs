//! SARIF `fixes[].artifactChanges[].artifactLocation.uri` must percent-encode
//! absolute unicode paths the same way as result `locations[]` URIs.

use keyhog_core::{MatchLocation, Reporter, SarifReporter, Severity, VerificationResult, VerifiedFinding};
use std::borrow::Cow;
use std::collections::HashMap;

fn synthetic_finding(path: &str) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "test-detector".into(),
        detector_name: "Test Detector".into(),
        service: "test".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("****redacted"),
        credential_hash: "abcdefabcdefabcdef".into(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some(path.into()),
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
fn sarif_fix_uri_percent_encodes_absolute_unicode_path() {
    let mut buf = Vec::new();
    {
        let mut r = SarifReporter::new(&mut buf);
        r.report(&synthetic_finding("/tmp/réport.json"))
            .expect("report");
        r.finish().expect("finish");
    }
    let json: serde_json::Value = serde_json::from_slice(&buf).expect("valid JSON");
    let result = &json["runs"][0]["results"][0];
    let loc_uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        .as_str()
        .expect("location uri");
    let fix_uri = result["fixes"][0]["artifactChanges"][0]["artifactLocation"]["uri"]
        .as_str()
        .expect("fix uri");
    assert!(
        loc_uri.contains("%C3%A9"),
        "location uri must percent-encode unicode, got {loc_uri}"
    );
    assert_eq!(
        fix_uri, loc_uri,
        "fix artifact uri must match location uri encoding"
    );
}
