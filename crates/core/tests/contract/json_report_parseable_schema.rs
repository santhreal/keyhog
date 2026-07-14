//! Contract: the legacy JSON array reporter remains parseable for library
//! callers, while the operator envelope carries a validated schema version.

use crate::support::reporters::JsonArrayReporter;
use keyhog_core::{
    write_scan_report, JsonReportEnvelope, MatchLocation, ReportFormat, ScanReport,
    ScanReportMetadata, Severity, VerificationResult, VerifiedFinding,
};
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
        companions_redacted: std::collections::HashMap::new(),
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
        entropy: None,
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

#[test]
fn versioned_json_envelope_validates_major_and_accepts_minor() {
    let finding = sample_finding();
    let metadata = ScanReportMetadata {
        keyhog_version: "0.5.41".into(),
        generated_at: "2026-07-14T00:00:00".into(),
        scan_started_at: "2026-07-14T00:00:00".into(),
        scan_finished_at: "2026-07-14T00:00:01".into(),
        duration_ms: 1000,
        targets: vec!["fixture.env".into()],
        source_chunks_scanned: 1,
        detector_count: 922,
    };
    let mut buf = Vec::new();
    write_scan_report(
        &mut buf,
        ReportFormat::JsonEnvelope,
        ScanReport::new(std::slice::from_ref(&finding)).with_metadata(&metadata),
    )
    .expect("versioned JSON report writes");

    let text = String::from_utf8(buf).expect("JSON envelope is UTF-8");
    let parsed = JsonReportEnvelope::parse(&text).expect("current major parses");
    assert_eq!(parsed.schema_version.major, 1);
    assert_eq!(parsed.schema_version.minor, 0);
    assert_eq!(
        parsed.metadata.as_ref().expect("metadata").targets,
        ["fixture.env"]
    );
    assert_eq!(parsed.findings.len(), 1);

    let mut future_minor: serde_json::Value =
        serde_json::from_str(&text).expect("envelope JSON parses");
    future_minor["schema_version"]["minor"] = serde_json::json!(99);
    JsonReportEnvelope::parse(&future_minor.to_string())
        .expect("same-major additive minor must remain readable");

    let mut incompatible: serde_json::Value =
        serde_json::from_str(&text).expect("envelope JSON parses");
    incompatible["schema_version"]["major"] = serde_json::json!(2);
    let error = JsonReportEnvelope::parse(&incompatible.to_string())
        .expect_err("unsupported major must fail closed");
    assert!(
        error
            .to_string()
            .contains("unsupported JSON report schema major 2"),
        "major diagnostic must name the incompatible version: {error}"
    );
}
