//! JSON array reporter wraps emitted findings in a top-level array.

use keyhog_core::{
    JsonArrayReporter, MatchLocation, Reporter, Severity, VerificationResult, VerifiedFinding,
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
        credential_hash: [0; 32],
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
fn json_array_reporter_wraps_findings_in_array() {
    let mut buf = Vec::new();
    let mut reporter = JsonArrayReporter::new(&mut buf).unwrap();
    reporter.report(&sample_finding()).unwrap();
    reporter.finish().unwrap();
    let output = String::from_utf8(buf).unwrap();
    assert!(output.starts_with('['));
    assert!(output.ends_with(']'));
}
