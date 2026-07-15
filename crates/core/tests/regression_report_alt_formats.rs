//! Regression: EXACT reporter output bytes for the CSV, HTML, JUnit XML,
//! GitHub-Actions-annotation, and GitLab-SAST formats.
//!
//! Companion to `regression_report_output_bytes.rs` (which pins SARIF/JSON/
//! JSONL/text). Here every assertion is a concrete value: the exact header /
//! wrapper line each format ships, the exact placement of a single planted
//! finding's fields, and, for each streaming format, the exact empty-but-still
//! -valid document an all-clean scan produces. All values are computed by
//! reading the reporter source (`crates/core/src/report/{csv,html,junit,
//! github_annotations,gitlab_sast}.rs`), never guessed.
//!
//! No assertion is a bare `is_empty()`/`is_ok()`/`len()>0`: every check pins a
//! specific string, byte count, integer, or parsed-JSON value.

use keyhog_core::{
    write_csv_coverage_report, write_report, write_scan_report, CredentialHash, MatchLocation,
    ReportFormat, ScanCompletionStatus, ScanReport, ScanReportMetadata, Severity,
    VerificationResult, VerifiedFinding,
};
use std::borrow::Cow;
use std::collections::HashMap;

/// The exact CSV header keyhog writes on `CsvReporter::new`.
const CSV_HEADER: &str = "detector_id,detector_name,service,severity,credential_redacted,credential_hash,companions_redacted,source,file_path,line,offset,commit,author,date,verification,confidence,entropy,remediation,metadata,additional_locations";
const AWS_REMEDIATION_CSV: &str = r#""{""action"":""Disable or delete the exposed IAM access key, then rotate any paired secret access key and session token."",""revoke_url"":""https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_ManagingAccessKeys"",""docs_url"":""https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"",""revoke_command"":""aws iam update-access-key --access-key-id {{credential}} --status Inactive""}""#;

/// GitLab SAST schema version and URL pinned by the reporter.
const GITLAB_SCHEMA_VERSION: &str = "15.2.4";
const GITLAB_SCHEMA_URL: &str = "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/master/dist/sast-report-format.json";
const GITLAB_SOLUTION: &str = "Rotate this credential, revoke the exposed value, and load the replacement from a secret manager or CI secret variable.";

/// The canonical planted finding: a High-severity AWS access key at
/// `config/app.env:7`, credential hash all `0xAB`, confidence exactly 0.9,
/// verification `Unverifiable` (token "unverifiable").
fn planted() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS Access Key".into(),
        service: "aws".into(),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA****"),
        credential_hash: CredentialHash::from_bytes([0xAB; 32]),
        companions_redacted: std::collections::HashMap::new(),
        location: MatchLocation {
            source: "filesystem".into(),
            file_path: Some("config/app.env".into()),
            line: Some(7),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Unverifiable,
        metadata: HashMap::new(),
        additional_locations: vec![],
        entropy: None,
        confidence: Some(0.9),
    }
}

/// The lower-hex form of a 32-byte all-`0xAB` credential hash.
fn hash_hex() -> String {
    "ab".repeat(32)
}

fn render(format: ReportFormat, findings: &[VerifiedFinding]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_report(&mut buf, format, findings).expect("write_report must succeed");
    buf
}

fn render_str(format: ReportFormat, findings: &[VerifiedFinding]) -> String {
    String::from_utf8(render(format, findings)).expect("report output must be valid UTF-8")
}

/// True iff `text` contains `line` as a complete `\n`-delimited line.
fn has_line(text: &str, line: &str) -> bool {
    text.lines().any(|l| l == line)
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

fn test_metadata(scan_status: ScanCompletionStatus) -> ScanReportMetadata {
    ScanReportMetadata {
        scan_id: "0123456789abcdef0123456789abcdef".into(),
        scan_status,
        keyhog_version: "test".into(),
        git_hash: "test".into(),
        detector_digest: "test".into(),
        config_digest: None,
        generated_at: "2026-01-01T00:00:00".into(),
        scan_started_at: "2026-01-01T00:00:00".into(),
        scan_finished_at: "2026-01-01T00:00:01".into(),
        duration_ms: 1,
        targets: vec!["fixture".into()],
        source_chunks_scanned: 0,
        source_bytes_scanned: 0,
        detector_count: 1,
    }
}

/// Positive: the CSV report's first line is the fixed 20-column header verbatim.
#[test]
fn csv_header_is_exact_first_line() {
    let out = render_str(ReportFormat::Csv, &[planted()]);
    let first = out.lines().next().expect("CSV must have a header line");
    assert_eq!(first, CSV_HEADER);
}

/// Positive: the single planted finding renders as one exact CSV data row, with
/// the three absent git fields (commit/author/date) as empty cells and
/// confidence as the plain `f64` string `0.9`.
#[test]
fn csv_planted_finding_row_is_exact() {
    let out = render_str(ReportFormat::Csv, &[planted()]);
    let expected_row = format!(
        "aws-access-key,AWS Access Key,aws,high,AKIA****,{},{{}},filesystem,config/app.env,7,0,,,,unverifiable,0.9,,{AWS_REMEDIATION_CSV},{{}},[]",
        hash_hex()
    );
    assert!(
        has_line(&out, &expected_row),
        "expected CSV row not found.\nwant: {expected_row}\ngot:\n{out}"
    );
    // Exactly one header + one data row => two non-empty lines.
    assert_eq!(out.lines().count(), 2);
}

/// Negative twin: an empty (all-clean) scan yields the header line and nothing
/// else (a still-valid, single-line CSV document).
#[test]
fn csv_empty_run_is_header_only() {
    let out = render_str(ReportFormat::Csv, &[]);
    assert_eq!(out, format!("{CSV_HEADER}\n"));
    assert_eq!(out.lines().count(), 1);
}

#[test]
fn csv_coverage_preamble_preserves_zero_finding_partial_status() {
    let metadata = test_metadata(ScanCompletionStatus::Partial);
    let mut buf = Vec::new();
    write_csv_coverage_report(
        &mut buf,
        ScanReport::new(&[]).with_metadata(&metadata),
        &[("unreadable source".into(), 2)],
    )
    .expect("CSV coverage report");
    let out = String::from_utf8(buf).expect("CSV is UTF-8");
    let mut lines = out.lines();
    assert_eq!(
        lines.next(),
        Some("# keyhog.scan.metadata={\"schema_version\":1,\"scan_status\":\"partial\",\"coverage_gap_summary\":[{\"reason\":\"unreadable source\",\"count\":2}]}")
    );
    assert_eq!(lines.next(), Some(CSV_HEADER));
    assert_eq!(lines.next(), None);
}

#[test]
fn versioned_json_reports_preserve_explicit_failed_status() {
    let metadata = test_metadata(ScanCompletionStatus::Failed);
    let report = ScanReport::new(&[]).with_metadata(&metadata);

    let mut json = Vec::new();
    write_scan_report(
        &mut json,
        ReportFormat::JsonEnvelope {
            coverage_gap_summary: Vec::new(),
        },
        report,
    )
    .expect("failed JSON envelope report");
    let json: serde_json::Value = serde_json::from_slice(&json).expect("JSON envelope parses");
    assert_eq!(json["scan_status"], "failed");
    assert_eq!(json["metadata"]["scan_status"], "failed");

    let mut jsonl = Vec::new();
    write_scan_report(
        &mut jsonl,
        ReportFormat::JsonlEnvelope {
            coverage_gap_summary: Vec::new(),
        },
        report,
    )
    .expect("failed JSONL envelope report");
    let records: Vec<serde_json::Value> = String::from_utf8(jsonl)
        .expect("JSONL UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSONL record parses"))
        .collect();
    assert_eq!(records[0]["metadata"]["scan_status"], "failed");
    assert_eq!(records[1]["scan_status"], "failed");
}

#[test]
fn structured_projections_preserve_explicit_failed_and_cancelled_status() {
    for status in [
        ScanCompletionStatus::Failed,
        ScanCompletionStatus::Cancelled,
    ] {
        let metadata = test_metadata(status);
        let report = ScanReport::new(&[]).with_metadata(&metadata);

        let mut sarif = Vec::new();
        write_scan_report(
            &mut sarif,
            ReportFormat::Sarif {
                skip_summary: Vec::new(),
            },
            report,
        )
        .expect("SARIF report");
        let sarif: serde_json::Value = serde_json::from_slice(&sarif).expect("SARIF parses");
        assert_eq!(
            sarif["runs"][0]["properties"]["keyhog.scan.status"],
            serde_json::to_value(status).expect("status serializes")
        );

        let mut annotations = Vec::new();
        write_scan_report(
            &mut annotations,
            ReportFormat::GithubAnnotationsCoverage {
                skip_summary: Vec::new(),
            },
            report,
        )
        .expect("GitHub annotations report");
        let annotations = String::from_utf8(annotations).expect("annotations are UTF-8");
        let label = serde_json::to_string(&status)
            .expect("status serializes")
            .trim_matches('"')
            .to_string();
        assert_eq!(
            annotations,
            format!("::notice title=keyhog scan::scan status: {label}\n")
        );

        let mut junit = Vec::new();
        write_scan_report(
            &mut junit,
            ReportFormat::JunitCoverage {
                skip_summary: Vec::new(),
            },
            report,
        )
        .expect("JUnit report");
        let junit = String::from_utf8(junit).expect("JUnit is UTF-8");
        assert!(junit.contains(&format!("name=\"keyhog.scan.status\" value=\"{label}\"")));

        let mut gitlab = Vec::new();
        write_scan_report(
            &mut gitlab,
            ReportFormat::GitlabSastCoverage {
                scan_started_at: "2026-01-01T00:00:00".into(),
                scan_finished_at: "2026-01-01T00:00:01".into(),
                skip_summary: Vec::new(),
            },
            report,
        )
        .expect("GitLab report");
        let gitlab: serde_json::Value = serde_json::from_slice(&gitlab).expect("GitLab parses");
        assert_eq!(gitlab["scan"]["status"], "failure");
        assert_eq!(gitlab["scan"]["keyhog_scan_status"], label);
    }
}

#[test]
fn structured_projection_matrix_preserves_declared_fields() {
    let mut finding = planted();
    finding
        .companions_redacted
        .insert("account".into(), "12...34".into());
    finding.metadata.insert("scope".into(), "read".into());
    finding.additional_locations.push(MatchLocation {
        source: "git".into(),
        file_path: Some("history.env".into()),
        line: Some(19),
        offset: 4,
        commit: Some("deadbeef".into()),
        author: None,
        date: None,
    });
    finding.entropy = Some(4.25);
    finding.confidence = Some(0.875);

    let json: serde_json::Value = serde_json::from_slice(&render(
        ReportFormat::JsonEnvelope {
            coverage_gap_summary: Vec::new(),
        },
        &[finding.clone()],
    ))
    .expect("JSON envelope parses");
    let json_finding = &json["findings"][0];
    assert_eq!(json_finding["metadata"]["scope"], "read");
    assert_eq!(
        json_finding["additional_locations"][0]["file_path"],
        "history.env"
    );
    assert_eq!(json_finding["confidence"], 0.875);
    assert_eq!(json_finding["entropy"], 4.25);

    let jsonl_lines: Vec<serde_json::Value> = render(
        ReportFormat::JsonlEnvelope {
            coverage_gap_summary: Vec::new(),
        },
        &[finding.clone()],
    )
    .split(|byte| *byte == b'\n')
    .filter(|line| !line.is_empty())
    .map(|line| serde_json::from_slice(line).expect("JSONL record parses"))
    .collect();
    assert_eq!(jsonl_lines[1]["metadata"]["scope"], "read");
    assert_eq!(jsonl_lines[1]["additional_locations"][0]["offset"], 4);

    let sarif: serde_json::Value = serde_json::from_slice(&render(
        ReportFormat::Sarif {
            skip_summary: Vec::new(),
        },
        &[finding],
    ))
    .expect("SARIF parses");
    let result = &sarif["runs"][0]["results"][0];
    assert_eq!(result["ruleId"], "aws-access-key");
    assert_eq!(result["properties"]["metadata.scope"], "read");
    assert_eq!(
        result["properties"]["companions_redacted.account"],
        "12...34"
    );
    assert_eq!(result["properties"]["confidence"], 0.875);
    assert_eq!(result["properties"]["entropy"], 4.25);
    assert_eq!(
        result["relatedLocations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        "history.env"
    );
}

// ---------------------------------------------------------------------------
// JUnit XML
// ---------------------------------------------------------------------------

/// Negative twin: an empty scan produces the exact well-formed JUnit skeleton
/// with `tests="0" failures="0"` and no testcases.
#[test]
fn junit_empty_run_is_exact_document() {
    let out = render_str(ReportFormat::Junit, &[]);
    let expected = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<testsuites>\n",
        "  <testsuite name=\"keyhog\" tests=\"0\" failures=\"0\" errors=\"0\" time=\"0.0\">\n",
        "    <properties>\n",
        "      <property name=\"keyhog.scan.status\" value=\"success\"/>\n",
        "    </properties>\n",
        "  </testsuite>\n",
        "</testsuites>\n",
    );
    assert_eq!(out, expected);
}

#[test]
fn junit_coverage_properties_make_partial_scans_machine_visible() {
    let mut buf = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::JunitCoverage {
            skip_summary: vec![
                ("oversize & <file>".to_string(), 2),
                ("unreadable source".to_string(), 1),
            ],
        },
        &[],
    )
    .expect("junit coverage report");
    let out = String::from_utf8(buf).expect("junit is UTF-8");
    assert!(out.contains("name=\"keyhog.scan.status\" value=\"partial\""));
    assert!(out.contains("name=\"keyhog.coverage_gap\" value=\"oversize &amp; &lt;file&gt;=2\""));
    assert!(out.contains("name=\"keyhog.coverage_gap\" value=\"unreadable source=1\""));
}

/// Positive: the planted finding drives `tests="1" failures="1"`, and the
/// testcase name is `<file>:<line>:<detector_id>` with the fixed classname.
#[test]
fn junit_planted_finding_suite_and_testcase_lines() {
    let out = render_str(ReportFormat::Junit, &[planted()]);
    assert!(has_line(
        &out,
        "  <testsuite name=\"keyhog\" tests=\"1\" failures=\"1\" errors=\"0\" time=\"0.0\">"
    ));
    assert!(has_line(
        &out,
        "    <testcase name=\"config/app.env:7:aws-access-key\" classname=\"keyhog.findings\" time=\"0.0\">"
    ));
    assert!(has_line(
        &out,
        "      <failure message=\"Secret detected: AWS Access Key (id: aws-access-key)\" type=\"high\">"
    ));
}

/// Positive: the CDATA body reproduces each finding field with the reporter's
/// fixed column alignment and exact values.
#[test]
fn junit_planted_finding_cdata_body_fields() {
    let out = render_str(ReportFormat::Junit, &[planted()]);
    for expected in [
        "Detector Name: AWS Access Key".to_string(),
        "Detector ID:   aws-access-key".to_string(),
        "Service:       aws".to_string(),
        "Severity:      high".to_string(),
        "Source:        filesystem".to_string(),
        "File Path:     config/app.env".to_string(),
        "Line:          7".to_string(),
        "Offset:        0".to_string(),
        "Redacted:      AKIA****".to_string(),
        format!("Hash:          {}", hash_hex()),
        "Verification:  unverifiable".to_string(),
        "Confidence:    0.9".to_string(),
    ] {
        assert!(
            has_line(&out, &expected),
            "missing CDATA line: {expected:?}\nfull output:\n{out}"
        );
    }
}

// ---------------------------------------------------------------------------
// GitHub Actions annotations
// ---------------------------------------------------------------------------

/// Positive: a High finding with a file+line emits one `::error` workflow
/// command with `file`, `line`, `title` properties and the full message,
/// confidence formatted to 3 decimals.
#[test]
fn github_planted_finding_is_exact_line() {
    let out = render_str(ReportFormat::GithubAnnotations, &[planted()]);
    let expected = "::error file=config/app.env,line=7,title=keyhog high aws-access-key::AWS Access Key detector=aws-access-key service=aws redacted=AKIA**** verification=unverifiable confidence=0.900";
    assert!(
        has_line(&out, expected),
        "want annotation line:\n{expected}\ngot:\n{out}"
    );
    assert_eq!(out.lines().count(), 1);
}

/// Negative twin: an empty scan produces zero bytes (no annotations at all).
#[test]
fn github_empty_run_is_zero_bytes() {
    let out = render(ReportFormat::GithubAnnotations, &[]);
    assert_eq!(out.len(), 0);
    assert_eq!(String::from_utf8(out).unwrap(), "");
}

/// Boundary/mapping twin: a Medium finding with NO file or line maps to
/// `::warning`, omits the file/line properties, and leads with `title`.
#[test]
fn github_medium_no_location_is_warning_title_only() {
    let mut f = planted();
    f.severity = Severity::Medium;
    f.location.file_path = None;
    f.location.line = None;
    let out = render_str(ReportFormat::GithubAnnotations, &[f]);
    let expected = "::warning title=keyhog medium aws-access-key::AWS Access Key detector=aws-access-key service=aws redacted=AKIA**** verification=unverifiable confidence=0.900";
    assert!(
        has_line(&out, expected),
        "want warning line:\n{expected}\ngot:\n{out}"
    );
}

// ---------------------------------------------------------------------------
// GitLab SAST security report JSON
// ---------------------------------------------------------------------------

fn render_gitlab_json(findings: &[VerifiedFinding]) -> serde_json::Value {
    let buf = render(
        ReportFormat::GitlabSast {
            scan_started_at: "2026-01-01T00:00:00".to_string(),
            scan_finished_at: "2026-01-01T00:05:00".to_string(),
        },
        findings,
    );
    serde_json::from_slice(&buf).expect("GitLab SAST output must parse as JSON")
}

/// Negative twin: an empty scan still emits a complete, schema-valid document
/// with fixed version/schema/scan metadata and empty `vulnerabilities`.
#[test]
fn gitlab_empty_run_is_valid_document() {
    let v = render_gitlab_json(&[]);
    assert_eq!(v["version"].as_str(), Some(GITLAB_SCHEMA_VERSION));
    assert_eq!(v["schema"].as_str(), Some(GITLAB_SCHEMA_URL));
    assert_eq!(v["scan"]["type"].as_str(), Some("sast"));
    assert_eq!(v["scan"]["status"].as_str(), Some("success"));
    assert_eq!(
        v["scan"]["start_time"].as_str(),
        Some("2026-01-01T00:00:00")
    );
    assert_eq!(v["scan"]["end_time"].as_str(), Some("2026-01-01T00:05:00"));
    assert_eq!(v["scan"]["analyzer"]["id"].as_str(), Some("keyhog"));
    assert_eq!(v["scan"]["analyzer"]["name"].as_str(), Some("KeyHog"));
    assert_eq!(
        v["scan"]["analyzer"]["vendor"]["name"].as_str(),
        Some("Santh Security")
    );
    let vulns = v["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities is an array");
    assert_eq!(vulns.len(), 0);
    let rem = v["remediations"].as_array().expect("remediations is array");
    assert_eq!(rem.len(), 0);
}

/// Positive: the planted finding becomes exactly one vulnerability with the
/// composed id, name, message, severity, location, identifier, and detail
/// values the reporter builds.
#[test]
fn gitlab_planted_finding_vulnerability_fields() {
    let v = render_gitlab_json(&[planted()]);
    let vulns = v["vulnerabilities"].as_array().expect("array");
    assert_eq!(vulns.len(), 1);
    let vuln = &vulns[0];
    assert_eq!(vuln["category"].as_str(), Some("sast"));
    assert_eq!(vuln["name"].as_str(), Some("aws credential detected"));
    assert_eq!(vuln["severity"].as_str(), Some("High"));
    assert_eq!(vuln["solution"].as_str(), Some(GITLAB_SOLUTION));
    assert_eq!(vuln["location"]["file"].as_str(), Some("config/app.env"));
    assert_eq!(vuln["location"]["start_line"].as_u64(), Some(7));
    assert_eq!(
        vuln["id"].as_str(),
        Some(format!("keyhog:aws-access-key:{}:config/app.env:7", hash_hex()).as_str())
    );
    assert_eq!(
        vuln["message"].as_str(),
        Some("AWS Access Key found by aws-access-key at config/app.env:7")
    );
    let idents = vuln["identifiers"].as_array().expect("identifiers array");
    assert_eq!(idents.len(), 1);
    assert_eq!(idents[0]["type"].as_str(), Some("keyhog_rule"));
    assert_eq!(idents[0]["name"].as_str(), Some("AWS Access Key"));
    assert_eq!(idents[0]["value"].as_str(), Some("aws-access-key"));
    assert_eq!(
        vuln["details"]["credential"]["value"].as_str(),
        Some("AKIA****")
    );
    assert_eq!(
        vuln["details"]["credential_hash"]["value"].as_str(),
        Some(hash_hex().as_str())
    );
    assert_eq!(vuln["details"]["service"]["value"].as_str(), Some("aws"));
}

/// Negative twin: GitLab SAST requires a file path; a finding without one makes
/// `write_report` fail closed with the actionable error (fields serialize but
/// the whole report errors before completing).
#[test]
fn gitlab_missing_file_path_fails_closed() {
    let mut f = planted();
    f.location.file_path = None;
    let mut buf = Vec::new();
    let err = write_report(
        &mut buf,
        ReportFormat::GitlabSast {
            scan_started_at: "s".to_string(),
            scan_finished_at: "e".to_string(),
        },
        &[f],
    )
    .expect_err("GitLab SAST must reject a finding with no file path");
    assert!(
        err.to_string().contains("requires a non-empty file path"),
        "unexpected error text: {err}"
    );
}

/// Boundary twin: a finding with a file but no line number is likewise rejected
/// (GitLab needs a one-based line for every vulnerability).
#[test]
fn gitlab_missing_line_fails_closed() {
    let mut f = planted();
    f.location.line = None;
    let mut buf = Vec::new();
    let err = write_report(
        &mut buf,
        ReportFormat::GitlabSast {
            scan_started_at: "s".to_string(),
            scan_finished_at: "e".to_string(),
        },
        &[f],
    )
    .expect_err("GitLab SAST must reject a finding with no line number");
    assert!(
        err.to_string().contains("requires a one-based line number"),
        "unexpected error text: {err}"
    );
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

/// Negative twin: an empty scan still emits the full HTML wrapper, and the
/// inlined data constants are the empty-but-valid literals `[]`, `[]`, `null`.
#[test]
fn html_empty_run_is_exact_wrapper_and_empty_data() {
    let out = render_str(
        ReportFormat::Html {
            skip_summary: Vec::new(),
            metadata: None,
        },
        &[],
    );
    let first = out.lines().next().expect("HTML has a first line");
    assert_eq!(first, "<!DOCTYPE html>");
    assert!(has_line(&out, "<html lang=\"en\" data-theme=\"keyhog\">"));
    assert!(has_line(&out, "  <title>KeyHog Secret Scan Report</title>"));
    assert!(has_line(&out, "    const rawFindings = [];"));
    assert!(has_line(&out, "    const coverageGaps = [];"));
    assert!(has_line(&out, "    const scanMetadata = null;"));
    let last = out.lines().last().expect("HTML has a last line");
    assert_eq!(last, "</html>");
}

/// Positive + adversarial: the planted finding is inlined into `rawFindings`
/// with exact serde field values, and the `/` in the file path is escaped to
/// `/` (the XSS-safe `<script>` inlining), never left as a literal slash.
#[test]
fn html_planted_finding_rawfindings_and_slash_escaped() {
    let out = render_str(
        ReportFormat::Html {
            skip_summary: Vec::new(),
            metadata: None,
        },
        &[planted()],
    );
    let raw_line = out
        .lines()
        .find(|l| l.trim_start().starts_with("const rawFindings ="))
        .expect("rawFindings line present");
    assert!(
        raw_line.contains("\"detector_id\":\"aws-access-key\""),
        "{raw_line}"
    );
    assert!(raw_line.contains("\"severity\":\"high\""), "{raw_line}");
    assert!(
        raw_line.contains("\"credential_redacted\":\"AKIA****\""),
        "{raw_line}"
    );
    assert!(
        raw_line.contains(&format!("\"credential_hash\":\"{}\"", hash_hex())),
        "{raw_line}"
    );
    assert!(
        raw_line.contains("\"verification\":\"unverifiable\""),
        "{raw_line}"
    );
    // XSS-safe escaping: the path slash must be `/`, not a bare `/`.
    assert!(
        raw_line.contains("\"file_path\":\"config\\u002fapp.env\""),
        "path slash must be unicode-escaped: {raw_line}"
    );
    assert!(
        !raw_line.contains("config/app.env"),
        "literal slash leaked into inline script: {raw_line}"
    );
}
