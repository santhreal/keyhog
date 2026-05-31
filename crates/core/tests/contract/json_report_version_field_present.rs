//! Contract: JSONL reporter emits one parseable object per finding line.

use keyhog_core::{
    JsonlReporter, MatchLocation, Reporter, Severity, VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

fn sample() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "test-detector".into(),
        detector_name: "Test".into(),
        service: "test".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("****"),
        credential_hash: [0; 32],
        location: MatchLocation {
            source: "fs".into(),
            file_path: Some("a.env".into()),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.5),
    }
}

#[test]
fn jsonl_report_emits_parseable_object_per_finding() {
    let mut buf = Vec::new();
    {
        let mut r = JsonlReporter::new(&mut buf);
        r.report(&sample()).expect("report");
        r.finish().expect("finish");
    }
    let line = std::str::from_utf8(&buf).expect("utf8").trim();
    let parsed: serde_json::Value = serde_json::from_str(line).expect("jsonl line parses");
    assert_eq!(parsed["detector_id"].as_str(), Some("test-detector"));
}
