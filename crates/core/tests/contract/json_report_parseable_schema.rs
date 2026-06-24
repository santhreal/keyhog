//! Contract: JSON array reporter output is a parseable findings list whose
//! elements round-trip through the [`VerifiedFinding`] serde schema.

use crate::support::reporters::JsonArrayReporter;
use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
use std::borrow::Cow;
use std::collections::HashMap;

fn sample_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "oracle-detector".into(),
        detector_name: "Oracle Detector".into(),
        service: "oracle".into(),
        severity: Severity::Critical,
        credential_redacted: Cow::Borrowed("sk_****7890"),
        credential_hash: [0; 32].into(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("secrets.env".into()),
            line: Some(42),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Skipped,
        metadata: HashMap::from([("team".into(), "acme".into())]),
        additional_locations: vec![],
        confidence: Some(0.88),
    }
}

/// JSON report must expose a parseable top-level findings array.
#[test]
fn json_report_parseable_schema() {
    let mut buf = Vec::new();
    {
        let mut reporter = JsonArrayReporter::new(&mut buf).expect("open JSON array report");
        reporter
            .report(&sample_finding())
            .expect("write finding to JSON report");
        reporter.finish().expect("finish JSON array report");
    }

    let findings_value: serde_json::Value =
        serde_json::from_slice(&buf).expect("JSON report body must parse as JSON");

    let findings_array = findings_value
        .as_array()
        .expect("JSON report body must be a top-level findings array");

    assert_eq!(
        findings_array.len(),
        1,
        "expected exactly one finding in the JSON report array"
    );

    let findings: Vec<VerifiedFinding> =
        serde_json::from_value(findings_value).expect("findings must match VerifiedFinding schema");

    assert_eq!(findings[0].detector_id.as_ref(), "oracle-detector");
    assert_eq!(findings[0].service.as_ref(), "oracle");
    assert_eq!(findings[0].verification, VerificationResult::Skipped);
    assert_eq!(
        findings[0].location.file_path.as_deref(),
        Some("secrets.env")
    );
    assert_eq!(findings[0].location.line, Some(42));
    assert_eq!(
        findings[0].metadata.get("team").map(String::as_str),
        Some("acme")
    );
}
