use super::report_common::sample_finding;
use keyhog_core::{write_report, ReportFormat, VerifiedFinding};

fn format() -> ReportFormat {
    ReportFormat::GitlabSast {
        scan_started_at: "2026-06-17T10:00:00".to_string(),
        scan_finished_at: "2026-06-17T10:00:01".to_string(),
    }
}

fn render(findings: &[VerifiedFinding]) -> serde_json::Value {
    let mut buf: Vec<u8> = Vec::new();
    write_report(&mut buf, format(), findings).expect("render GitLab SAST");
    serde_json::from_slice(&buf).expect("valid GitLab SAST JSON")
}

#[test]
fn gitlab_sast_empty_report_has_required_scan_envelope() {
    let report = render(&[]);

    assert_eq!(report["version"], "15.2.4");
    assert!(report["schema"]
        .as_str()
        .expect("schema url")
        .contains("sast-report-format.json"));
    assert_eq!(report["scan"]["type"], "sast");
    assert_eq!(report["scan"]["status"], "success");
    assert_eq!(report["scan"]["start_time"], "2026-06-17T10:00:00");
    assert_eq!(report["scan"]["end_time"], "2026-06-17T10:00:01");
    assert_eq!(report["scan"]["scanner"]["id"], "keyhog");
    assert_eq!(
        report["vulnerabilities"]
            .as_array()
            .expect("vulnerabilities array")
            .len(),
        0
    );
    assert_eq!(
        report["remediations"]
            .as_array()
            .expect("remediations array")
            .len(),
        0
    );
}

#[test]
fn gitlab_sast_finding_has_required_vulnerability_fields() {
    let finding = sample_finding();
    let report = render(std::slice::from_ref(&finding));
    let vulnerabilities = report["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert_eq!(vulnerabilities.len(), 1);
    let vuln = &vulnerabilities[0];

    assert_eq!(vuln["category"], "sast");
    assert_eq!(vuln["severity"], "High");
    assert_eq!(vuln["location"]["file"], "config/app.env");
    assert_eq!(vuln["location"]["start_line"], 12);
    assert_eq!(vuln["identifiers"][0]["type"], "keyhog_rule");
    assert_eq!(vuln["identifiers"][0]["value"], "aws-access-key");
    assert_eq!(vuln["details"]["credential"]["value"], "AKIA...7XYA");
    assert!(
        vuln["id"].as_str().expect("id string").contains("deadbeef"),
        "stable id must include the credential hash"
    );
}

#[test]
fn gitlab_sast_rejects_findings_without_file_or_line() {
    let mut missing_file = sample_finding();
    missing_file.location.file_path = None;
    let mut buf = Vec::new();
    let error = write_report(&mut buf, format(), &[missing_file]).expect_err("missing file error");
    assert!(
        error.to_string().contains("requires a non-empty file path"),
        "error must explain the GitLab SAST file-path requirement: {error}"
    );

    let mut missing_line = sample_finding();
    missing_line.location.line = None;
    let mut buf = Vec::new();
    let error = write_report(&mut buf, format(), &[missing_line]).expect_err("missing line error");
    assert!(
        error
            .to_string()
            .contains("requires a one-based line number"),
        "error must explain the GitLab SAST line requirement: {error}"
    );
}
