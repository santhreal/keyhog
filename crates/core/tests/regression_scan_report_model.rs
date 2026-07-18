//! Regression: every formatter must receive the same format-neutral report
//! model. Metadata used to be assembled in the CLI and attached only to HTML,
//! which made the GitLab projection silently disagree with the scan record.

use keyhog_core::{
    write_csv_coverage_report, write_scan_report, ReportFormat, ResolvedScanManifest,
    ScanBackendRecoverySummary, ScanReport, ScanReportMetadata,
};
use std::collections::BTreeMap;

fn metadata() -> ScanReportMetadata {
    ScanReportMetadata {
        scan_id: "scan-test-id".to_string(),
        scan_status: keyhog_core::ScanCompletionStatus::Success,
        backend_recoveries: Vec::new(),
        keyhog_version: "0.5.41-test".to_string(),
        git_hash: "test-git".to_string(),
        detector_digest: "922-test".to_string(),
        config_digest: Some("0000000000000001".to_string()),
        resolved_scan: None,
        generated_at: "2026-07-14T12:00:02".to_string(),
        scan_started_at: "2026-07-14T12:00:00".to_string(),
        scan_finished_at: "2026-07-14T12:00:02".to_string(),
        duration_ms: 2_000,
        targets: vec!["repo".to_string()],
        source_chunks_scanned: 3,
        source_bytes_scanned: 192,
        detector_count: 922,
    }
}

#[test]
fn html_and_gitlab_project_the_same_scan_metadata() {
    let metadata = metadata();
    let report = ScanReport::new(&[]).with_metadata(&metadata);

    let mut html = Vec::new();
    write_scan_report(
        &mut html,
        ReportFormat::Html {
            skip_summary: Vec::new(),
            metadata: None,
        },
        report,
    )
    .expect("HTML report must render");
    let html = String::from_utf8(html).expect("HTML output is UTF-8");
    assert!(html.contains("2026-07-14T12:00:00"));
    assert!(html.contains("2026-07-14T12:00:02"));
    assert!(html.contains("\"detector_count\":922"));

    let mut gitlab = Vec::new();
    write_scan_report(
        &mut gitlab,
        ReportFormat::GitlabSast {
            scan_started_at: metadata.scan_started_at.clone(),
            scan_finished_at: metadata.scan_finished_at.clone(),
        },
        report,
    )
    .expect("GitLab report must render");
    let gitlab: serde_json::Value = serde_json::from_slice(&gitlab).expect("valid GitLab JSON");
    let scan = &gitlab["scan"];
    assert_eq!(scan["start_time"], metadata.scan_started_at);
    assert_eq!(scan["end_time"], metadata.scan_finished_at);
}

#[test]
fn conflicting_format_metadata_fails_closed() {
    let metadata = metadata();
    let mut output = Vec::new();
    let error = write_scan_report(
        &mut output,
        ReportFormat::GitlabSast {
            scan_started_at: "wrong-start".to_string(),
            scan_finished_at: metadata.scan_finished_at.clone(),
        },
        ScanReport::new(&[]).with_metadata(&metadata),
    )
    .expect_err("conflicting report metadata must not be silently overridden");
    assert!(error.to_string().contains("scan_started_at"));
}

#[test]
fn json_metadata_embeds_resolved_scan_manifest() {
    let mut metadata = metadata();
    let mut effective = BTreeMap::new();
    effective.insert("max_decode_depth".to_string(), "3".to_string());
    effective.insert("entropy_enabled".to_string(), "true".to_string());
    metadata.resolved_scan = Some(ResolvedScanManifest {
        schema_version: 1,
        preset: "deep".to_string(),
        effective,
        overrides: vec!["max_decode_depth".to_string()],
    });
    let mut output = Vec::new();
    write_scan_report(
        &mut output,
        ReportFormat::JsonEnvelope {
            coverage_gap_summary: Vec::new(),
        },
        ScanReport::new(&[]).with_metadata(&metadata),
    )
    .expect("JSON envelope must render");
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(value["metadata"]["resolved_scan"]["preset"], "deep");
    assert_eq!(
        value["metadata"]["resolved_scan"]["effective"]["max_decode_depth"],
        "3"
    );
    assert_eq!(
        value["metadata"]["resolved_scan"]["overrides"][0],
        "max_decode_depth"
    );
}

#[test]
fn legacy_writer_still_accepts_html_metadata_alias() {
    let metadata = metadata();
    let mut output = Vec::new();
    keyhog_core::write_report(
        &mut output,
        ReportFormat::Html {
            skip_summary: Vec::new(),
            metadata: Some(metadata),
        },
        &[],
    )
    .expect("legacy writer must remain compatible");
    assert!(String::from_utf8(output)
        .expect("HTML output is UTF-8")
        .contains("0.5.41-test"));
}

#[test]
fn complete_after_recovery_is_successful_but_never_masks_a_coverage_gap() {
    use keyhog_core::ScanCompletionStatus;

    assert_eq!(
        ScanCompletionStatus::resolve(Some(ScanCompletionStatus::CompleteAfterRecovery), false),
        ScanCompletionStatus::CompleteAfterRecovery
    );
    assert_eq!(
        ScanCompletionStatus::resolve(Some(ScanCompletionStatus::CompleteAfterRecovery), true),
        ScanCompletionStatus::Partial
    );

    let mut metadata = metadata();
    metadata.scan_status = ScanCompletionStatus::CompleteAfterRecovery;
    metadata.backend_recoveries = vec![ScanBackendRecoverySummary {
        events: 1,
        failed_backend: "CUDA GPU".to_string(),
        recovery_backend: "Hyperscan CPU".to_string(),
        recovered_ranges: 2,
        recovered_chunks: 1,
        recovered_bytes: 4096,
        reason: "device reset".to_string(),
        repair_command: "keyhog calibrate-autoroute".to_string(),
    }];
    let mut output = Vec::new();
    write_scan_report(
        &mut output,
        ReportFormat::JsonEnvelope {
            coverage_gap_summary: Vec::new(),
        },
        ScanReport::new(&[]).with_metadata(&metadata),
    )
    .expect("recovered complete report must render");
    let value: serde_json::Value = serde_json::from_slice(&output).expect("valid JSON");
    assert_eq!(value["scan_status"], "complete_after_recovery");
    assert_eq!(value["metadata"]["scan_status"], "complete_after_recovery");
    assert_eq!(
        value["metadata"]["backend_recoveries"][0]["recovered_bytes"],
        4096
    );

    let mut partial = Vec::new();
    write_scan_report(
        &mut partial,
        ReportFormat::JsonEnvelope {
            coverage_gap_summary: vec![("unreadable source".to_string(), 1)],
        },
        ScanReport::new(&[]).with_metadata(&metadata),
    )
    .expect("coverage gap report must render");
    let partial: serde_json::Value = serde_json::from_slice(&partial).expect("valid JSON");
    assert_eq!(partial["scan_status"], "partial");
    assert_eq!(partial["metadata"]["backend_recoveries"][0]["events"], 1);
}

#[test]
fn recovery_summary_projects_into_ci_artifacts() {
    let mut metadata = metadata();
    metadata.scan_status = keyhog_core::ScanCompletionStatus::CompleteAfterRecovery;
    metadata.backend_recoveries = vec![ScanBackendRecoverySummary {
        events: 2,
        failed_backend: "CUDA GPU".to_string(),
        recovery_backend: "Hyperscan CPU".to_string(),
        recovered_ranges: 3,
        recovered_chunks: 2,
        recovered_bytes: 8192,
        reason: "device reset".to_string(),
        repair_command: "keyhog calibrate-autoroute".to_string(),
    }];
    let report = ScanReport::new(&[]).with_metadata(&metadata);

    let mut sarif = Vec::new();
    write_scan_report(
        &mut sarif,
        ReportFormat::Sarif {
            skip_summary: Vec::new(),
        },
        report,
    )
    .expect("SARIF report must render");
    let sarif: serde_json::Value = serde_json::from_slice(&sarif).expect("valid SARIF");
    assert_eq!(
        sarif["runs"][0]["properties"]["keyhog.backend.recoveries"][0]["recovered_bytes"],
        8192
    );

    let mut junit = Vec::new();
    write_scan_report(&mut junit, ReportFormat::Junit, report).expect("JUnit report must render");
    let junit = String::from_utf8(junit).expect("JUnit is UTF-8");
    assert!(junit.contains("keyhog.backend.recovery"));
    assert!(junit.contains("&quot;recovered_bytes&quot;:8192"));

    let mut annotations = Vec::new();
    write_scan_report(&mut annotations, ReportFormat::GithubAnnotations, report)
        .expect("annotations must render");
    let annotations = String::from_utf8(annotations).expect("annotations are UTF-8");
    assert!(annotations.contains("keyhog backend recovery"));
    assert!(annotations.contains("8192 byte(s)"));
    assert!(annotations.contains("keyhog calibrate-autoroute"));

    let mut gitlab = Vec::new();
    write_scan_report(
        &mut gitlab,
        ReportFormat::GitlabSast {
            scan_started_at: metadata.scan_started_at.clone(),
            scan_finished_at: metadata.scan_finished_at.clone(),
        },
        report,
    )
    .expect("GitLab report must render");
    let gitlab: serde_json::Value = serde_json::from_slice(&gitlab).expect("valid GitLab JSON");
    assert_eq!(
        gitlab["scan"]["keyhog_backend_recoveries"][0]["recovery_backend"],
        "Hyperscan CPU"
    );

    let mut csv = Vec::new();
    write_csv_coverage_report(&mut csv, report, &[]).expect("CSV report must render");
    let preamble = std::str::from_utf8(&csv)
        .expect("CSV is UTF-8")
        .lines()
        .next()
        .expect("CSV preamble")
        .strip_prefix("# keyhog.scan.metadata=")
        .expect("CSV metadata prefix");
    let csv_metadata: serde_json::Value = serde_json::from_str(preamble).expect("CSV metadata");
    assert_eq!(csv_metadata["schema_version"], 2);
    assert_eq!(
        csv_metadata["backend_recoveries"][0]["failed_backend"],
        "CUDA GPU"
    );

    let mut html = Vec::new();
    write_scan_report(
        &mut html,
        ReportFormat::Html {
            skip_summary: Vec::new(),
            metadata: None,
        },
        report,
    )
    .expect("HTML report must render");
    let html = String::from_utf8(html).expect("HTML is UTF-8");
    assert!(html.contains("\"backend_recoveries\":[{\"events\":2"));
    assert!(html.contains("id=\"meta-backend-recovery\""));
}
