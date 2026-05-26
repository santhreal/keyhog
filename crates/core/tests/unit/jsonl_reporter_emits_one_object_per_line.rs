//! JSONL reporter emits one JSON object per reported finding.

use keyhog_core::{
    JsonlReporter, MatchLocation, Reporter, Severity, VerificationResult, VerifiedFinding,
};
use std::collections::HashMap;
use std::sync::Arc;

fn sample_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("demo"),
        detector_name: Arc::from("Demo"),
        service: Arc::from("demo"),
        severity: Severity::Low,
        credential_redacted: std::borrow::Cow::Borrowed("****"),
        credential_hash: "abc".into(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("app.env")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Skipped,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: None,
    }
}

#[test]
fn jsonl_reporter_emits_one_object_per_line() {
    let mut buf = Vec::new();
    let mut reporter = JsonlReporter::new(&mut buf);
    reporter.report(&sample_finding()).unwrap();
    reporter.finish().unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.trim().starts_with('{'));
}
