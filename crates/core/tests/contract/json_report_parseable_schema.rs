//! Contract: the legacy JSON array reporter remains parseable for library
//! callers, while the operator envelope carries a validated schema version.

use crate::support::reporters::JsonArrayReporter;
use keyhog_core::{
    parse_jsonl_stream, write_scan_report, JsonReportEnvelope, MatchLocation, ReportFormat,
    ScanReport, ScanReportMetadata, Severity, VerificationResult, VerifiedFinding,
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
        scan_id: "scan-test-id".into(),
        scan_status: keyhog_core::ScanCompletionStatus::Success,
        keyhog_version: "0.5.41".into(),
        git_hash: "test-git".into(),
        detector_digest: "922-test".into(),
        config_digest: Some("0000000000000001".into()),
        resolved_scan: None,
        generated_at: "2026-07-14T00:00:00".into(),
        scan_started_at: "2026-07-14T00:00:00".into(),
        scan_finished_at: "2026-07-14T00:00:01".into(),
        duration_ms: 1000,
        targets: vec!["fixture.env".into()],
        source_chunks_scanned: 1,
        source_bytes_scanned: 128,
        detector_count: 922,
    };
    let mut buf = Vec::new();
    write_scan_report(
        &mut buf,
        ReportFormat::JsonEnvelope {
            coverage_gap_summary: vec![("fixture skipped".into(), 1)],
        },
        ScanReport::new(std::slice::from_ref(&finding)).with_metadata(&metadata),
    )
    .expect("versioned JSON report writes");

    let text = String::from_utf8(buf).expect("JSON envelope is UTF-8");
    let parsed = JsonReportEnvelope::parse(&text).expect("current major parses");
    assert_eq!(parsed.schema_version.major, 1);
    assert_eq!(parsed.schema_version.minor, 5);
    assert_eq!(
        parsed.scan_status,
        keyhog_core::ScanCompletionStatus::Partial
    );
    assert_eq!(
        parsed.metadata.as_ref().expect("metadata").targets,
        ["fixture.env"]
    );
    assert_eq!(parsed.coverage_gap_summary[0].count, 1);
    assert_eq!(parsed.findings.len(), 1);

    let mut legacy = serde_json::to_value(&parsed).expect("parsed envelope serializes");
    legacy
        .as_object_mut()
        .expect("legacy envelope object")
        .remove("scan_status");
    legacy["metadata"]
        .as_object_mut()
        .expect("metadata object")
        .remove("scan_id");
    legacy["metadata"]
        .as_object_mut()
        .expect("metadata object")
        .remove("scan_status");
    let legacy = JsonReportEnvelope::parse(&legacy.to_string())
        .expect("reports without the additive scan id remain readable");
    assert_eq!(
        legacy.scan_status,
        keyhog_core::ScanCompletionStatus::Success
    );
    assert_eq!(
        legacy.metadata.as_ref().expect("legacy metadata").scan_id,
        ""
    );
    assert_eq!(
        legacy
            .metadata
            .as_ref()
            .expect("legacy metadata")
            .scan_status,
        keyhog_core::ScanCompletionStatus::Success
    );

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

#[test]
fn versioned_jsonl_headers_split_concatenated_streams_and_validate_major() {
    let finding = sample_finding();
    let mut first = Vec::new();
    write_scan_report(
        &mut first,
        ReportFormat::JsonlEnvelope {
            coverage_gap_summary: vec![("partial source".into(), 2)],
        },
        ScanReport::new(std::slice::from_ref(&finding)),
    )
    .expect("first JSONL stream writes");
    let mut second = Vec::new();
    write_scan_report(
        &mut second,
        ReportFormat::JsonlEnvelope {
            coverage_gap_summary: Vec::new(),
        },
        ScanReport::new(&[]),
    )
    .expect("second JSONL stream writes");

    let mut joined = first.clone();
    joined.extend_from_slice(&second);
    let streams = parse_jsonl_stream(std::str::from_utf8(&joined).expect("JSONL is UTF-8"))
        .expect("concatenated streams parse by header boundary");
    assert_eq!(streams.len(), 2);
    assert_eq!(streams[0].header.schema_version.minor, 6);
    assert_eq!(streams[0].findings.len(), 1);
    assert!(streams[0].is_complete());
    assert_eq!(
        streams[0].summary.as_ref().expect("summary").finding_count,
        1
    );
    assert_eq!(
        streams[0]
            .summary
            .as_ref()
            .expect("summary")
            .coverage_gap_summary[0]
            .count,
        2
    );
    assert_eq!(
        streams[0].summary.as_ref().expect("summary").scan_status,
        keyhog_core::ScanCompletionStatus::Partial
    );
    assert!(streams[1].findings.is_empty());
    assert!(streams[1].is_complete());
    assert_eq!(
        streams[1].summary.as_ref().expect("summary").scan_status,
        keyhog_core::ScanCompletionStatus::Success
    );

    let incomplete_text = std::str::from_utf8(&first)
        .expect("JSONL is UTF-8")
        .lines()
        .take(2)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    let incomplete = parse_jsonl_stream(&incomplete_text).expect("interrupted stream parses");
    assert_eq!(incomplete.len(), 1);
    assert!(!incomplete[0].is_complete());

    let mut additive = first.clone();
    let newline = additive
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("header newline");
    let mut additive_header: serde_json::Value =
        serde_json::from_slice(&additive[..newline]).expect("header JSON");
    additive_header["schema_version"]["minor"] = serde_json::json!(99);
    let replacement = format!("{}\n", additive_header);
    additive.splice(..=newline, replacement.into_bytes());
    parse_jsonl_stream(std::str::from_utf8(&additive).expect("JSONL is UTF-8"))
        .expect("same-major JSONL minor must remain readable");

    let mut incompatible = first;
    let header = incompatible
        .split(|byte| *byte == b'\n')
        .next()
        .expect("header line");
    let mut header_value: serde_json::Value = serde_json::from_slice(header).expect("header JSON");
    header_value["schema_version"]["major"] = serde_json::json!(2);
    let replacement = format!("{}\n", header_value);
    let newline = incompatible
        .iter()
        .position(|byte| *byte == b'\n')
        .expect("header newline");
    incompatible.splice(..=newline, replacement.into_bytes());
    let error = parse_jsonl_stream(std::str::from_utf8(&incompatible).expect("JSONL is UTF-8"))
        .expect_err("unsupported JSONL major must fail closed");
    assert!(error
        .to_string()
        .contains("unsupported JSONL report schema major 2"));
}
