//! Regression: every formatter must receive the same format-neutral report
//! model. Metadata used to be assembled in the CLI and attached only to HTML,
//! which made the GitLab projection silently disagree with the scan record.

use keyhog_core::{write_scan_report, ReportFormat, ScanReport, ScanReportMetadata};

fn metadata() -> ScanReportMetadata {
    ScanReportMetadata {
        keyhog_version: "0.5.41-test".to_string(),
        git_hash: "test-git".to_string(),
        detector_digest: "922-test".to_string(),
        config_digest: Some("0000000000000001".to_string()),
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
