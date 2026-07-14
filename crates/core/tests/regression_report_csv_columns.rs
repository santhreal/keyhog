//! Regression: EXACT column-by-column bytes of the `ReportFormat::Csv` reporter
//! (`crates/core/src/report/csv.rs` + `report/escape.rs::escape_csv`).
//!
//! Complements `regression_report_alt_formats.rs` (header / single planted row /
//! empty run) and `regression_csv_formula_injection.rs` (formula defang) by
//! pinning the parts those files do not: the 15-column ORDER and count, a fully
//! populated row with every git field present, empty cells for absent optional
//! fields (line/confidence), RFC-4180 quoting for a NON-formula comma / embedded
//! double-quote / embedded newline, the kebab-case severity strings for all six
//! severities, every verification token (incl. the `error: {e}` form), 3-finding
//! input-order preservation, and the 64-char lowercase-hex credential hash cell.
//!
//! Every expected value is computed by reading the reporter source, never
//! guessed. No assertion is a bare `is_empty()`/`is_ok()`/`len()>0`.

use std::borrow::Cow;
use std::collections::HashMap;

use keyhog_core::{
    hex_encode, write_report, CredentialHash, MatchLocation, ReportFormat, Severity,
    VerificationResult, VerifiedFinding,
};

/// The exact 16-column CSV header keyhog writes on `CsvReporter::new`.
const CSV_HEADER: &str = "detector_id,detector_name,service,severity,credential_redacted,credential_hash,companions_redacted,source,file_path,line,offset,commit,author,date,verification,confidence";

/// Render findings as a CSV document string.
fn render(findings: &[VerifiedFinding]) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(&mut buf, ReportFormat::Csv, findings).expect("csv report must finish");
    String::from_utf8(buf).expect("csv output must be valid UTF-8")
}

/// Lower-hex of an all-`0xAB` 32-byte credential hash (the baseline finding's).
fn hash_ab() -> String {
    "ab".repeat(32)
}

/// A fully benign baseline finding: High AWS key, `config/app.env:7`, offset 0,
/// no git commit/author/date, `Unverifiable`, confidence exactly 0.9. Renders as
/// `aws-access-key,AWS Access Key,aws,high,AKIA****,<hash>,filesystem,config/app.env,7,0,,,,unverifiable,0.9`.
fn base() -> VerifiedFinding {
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
        confidence: Some(0.9),
    }
}

/// The second physical logical row (index 1) split on commas. Only safe when no
/// field is RFC-4180 quoted (i.e. no field contains a comma/quote/newline).
fn data_columns(out: &str) -> Vec<String> {
    out.lines()
        .nth(1)
        .expect("csv must have a data row")
        .split(',')
        .map(|s| s.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Header + empty document
// ---------------------------------------------------------------------------

#[test]
fn csv_header_is_exactly_sixteen_columns_in_canonical_order() {
    let out = render(&[base()]);
    let header = out.lines().next().expect("csv must have a header line");
    assert_eq!(header, CSV_HEADER);
    assert_eq!(header.split(',').count(), 16);
}

#[test]
fn csv_empty_scan_is_header_line_and_exact_byte_length() {
    let out = render(&[]);
    assert_eq!(out, format!("{CSV_HEADER}\n"));
    // header bytes + the single trailing newline; header is pure ASCII.
    assert_eq!(out.len(), CSV_HEADER.len() + 1);
    assert_eq!(out.lines().count(), 1);
}

// ---------------------------------------------------------------------------
// Fully populated row (all optional git fields present)
// ---------------------------------------------------------------------------

#[test]
fn csv_fully_populated_row_places_every_field_exactly() {
    let mut f = base();
    f.detector_id = "github-pat".into();
    f.detector_name = "GitHub PAT".into();
    f.service = "github".into();
    f.severity = Severity::Critical;
    f.credential_redacted = Cow::Borrowed("ghp_****");
    f.credential_hash = CredentialHash::from_bytes([0x00; 32]);
    f.location = MatchLocation {
        source: "git".into(),
        file_path: Some("src/config.rs".into()),
        line: Some(42),
        offset: 1234,
        commit: Some("abc123".into()),
        author: Some("Jane Dev".into()),
        date: Some("2026-07-01".into()),
    };
    f.verification = VerificationResult::Live;
    f.confidence = Some(0.875);

    let out = render(&[f]);
    let expected = format!(
        "github-pat,GitHub PAT,github,critical,ghp_****,{},{{}},git,src/config.rs,42,1234,abc123,Jane Dev,2026-07-01,live,0.875",
        "00".repeat(32)
    );
    assert_eq!(out.lines().nth(1).expect("data row"), expected);
}

// ---------------------------------------------------------------------------
// Empty cells for absent optional fields
// ---------------------------------------------------------------------------

#[test]
fn csv_confidence_none_yields_empty_trailing_cell() {
    let mut f = base();
    f.confidence = None;
    let out = render(&[f]);
    let cols = data_columns(&out);
    assert_eq!(cols.len(), 16);
    assert_eq!(cols[14], "unverifiable");
    assert_eq!(cols[15], "");
    // The record ends immediately after the verification token's separator.
    assert!(out
        .lines()
        .nth(1)
        .expect("data row")
        .ends_with(",unverifiable,"));
}

#[test]
fn csv_line_none_yields_empty_line_cell_but_keeps_neighbours() {
    let mut f = base();
    f.location.line = None;
    let out = render(&[f]);
    let cols = data_columns(&out);
    assert_eq!(cols[8], "config/app.env"); // file_path still populated
    assert_eq!(cols[9], ""); // line cell empty
    assert_eq!(cols[10], "0"); // offset unaffected
}

// ---------------------------------------------------------------------------
// RFC-4180 quoting of non-formula special characters
// ---------------------------------------------------------------------------

#[test]
fn csv_non_formula_comma_field_is_quoted_not_split() {
    let mut f = base();
    f.detector_name = "AWS, Inc".into();
    let out = render(&[f]);
    let expected = format!(
        "aws-access-key,\"AWS, Inc\",aws,high,AKIA****,{},{{}},filesystem,config/app.env,7,0,,,,unverifiable,0.9",
        hash_ab()
    );
    assert_eq!(out.lines().nth(1).expect("data row"), expected);
}

#[test]
fn csv_embedded_double_quote_is_doubled_and_wrapped() {
    let mut f = base();
    f.detector_name = "He said \"hi\"".into();
    let out = render(&[f]);
    // escape_csv: inner `"` doubled, whole field wrapped => "He said ""hi"""
    let expected = format!(
        "aws-access-key,\"He said \"\"hi\"\"\",aws,high,AKIA****,{},{{}},filesystem,config/app.env,7,0,,,,unverifiable,0.9",
        hash_ab()
    );
    assert_eq!(out.lines().nth(1).expect("data row"), expected);
}

#[test]
fn csv_embedded_newline_field_is_quoted_as_single_record() {
    let mut f = base();
    f.location.author = Some("line1\nline2".into());
    let out = render(&[f]);
    // The raw newline forces RFC-4180 quoting so the record stays one logical row.
    assert!(
        out.contains(",\"line1\nline2\","),
        "author with embedded newline must be quoted: {out:?}"
    );
    // Header + a record whose quoted body spans two physical lines => 3 lines.
    assert_eq!(out.lines().count(), 3);
}

// ---------------------------------------------------------------------------
// Severity column: kebab-case for all six severities (client-safe, not clientsafe)
// ---------------------------------------------------------------------------

#[test]
fn csv_severity_column_is_kebab_case_for_all_variants() {
    let cases = [
        (Severity::Info, "info"),
        (Severity::ClientSafe, "client-safe"),
        (Severity::Low, "low"),
        (Severity::Medium, "medium"),
        (Severity::High, "high"),
        (Severity::Critical, "critical"),
    ];
    for (sev, expected) in cases {
        let mut f = base();
        f.severity = sev;
        let out = render(&[f]);
        let cols = data_columns(&out);
        assert_eq!(cols[3], expected, "severity {sev:?} rendered wrong");
    }
}

// ---------------------------------------------------------------------------
// Verification column: every canonical token, incl. the `error: {e}` form
// ---------------------------------------------------------------------------

#[test]
fn csv_verification_column_uses_canonical_tokens() {
    let cases = [
        (VerificationResult::Live, "live"),
        (VerificationResult::Revoked, "revoked"),
        (VerificationResult::Dead, "dead"),
        (VerificationResult::RateLimited, "rate_limited"),
        (VerificationResult::Skipped, "skipped"),
        (VerificationResult::Unverifiable, "unverifiable"),
    ];
    for (verification, expected) in cases {
        let mut f = base();
        f.verification = verification;
        let out = render(&[f]);
        let cols = data_columns(&out);
        assert_eq!(cols[14], expected, "verification token mismatch");
    }
}

#[test]
fn csv_verification_error_renders_error_prefix_and_message() {
    let mut f = base();
    f.verification = VerificationResult::Error("boom".to_string());
    let out = render(&[f]);
    let cols = data_columns(&out);
    assert_eq!(cols[14], "error: boom");
}

// ---------------------------------------------------------------------------
// Multi-finding ordering (reporter preserves input order, no sort)
// ---------------------------------------------------------------------------

#[test]
fn csv_three_findings_preserve_input_order_exact_document() {
    let mut a = base();
    a.detector_id = "a-one".into();
    let mut b = base();
    b.detector_id = "b-two".into();
    b.severity = Severity::Low;
    let mut c = base();
    c.detector_id = "c-three".into();
    c.severity = Severity::Critical;

    let out = render(&[a, b, c]);
    let hash = hash_ab();
    let row = |id: &str, sev: &str| {
        format!("{id},AWS Access Key,aws,{sev},AKIA****,{hash},{{}},filesystem,config/app.env,7,0,,,,unverifiable,0.9")
    };
    let expected = format!(
        "{}\n{}\n{}\n{}\n",
        CSV_HEADER,
        row("a-one", "high"),
        row("b-two", "low"),
        row("c-three", "critical")
    );
    assert_eq!(out, expected);
    assert_eq!(out.lines().count(), 4); // header + 3 rows
}

// ---------------------------------------------------------------------------
// Credential-hash cell + formula/benign boundary
// ---------------------------------------------------------------------------

#[test]
fn csv_credential_hash_cell_is_sixty_four_lowercase_hex() {
    let mut f = base();
    f.credential_hash = CredentialHash::from_bytes([0x0F; 32]);
    let out = render(&[f]);
    let cols = data_columns(&out);
    assert_eq!(cols[5].len(), 64);
    assert_eq!(cols[5], "0f".repeat(32));
    // Cross-check against the public hex encoder used by the reporter.
    assert_eq!(cols[5], hex_encode([0x0F; 32]));
}

#[test]
fn csv_formula_prefix_with_comma_is_guarded_then_quoted() {
    let mut f = base();
    f.service = "=A1,B1".into();
    let out = render(&[f]);
    // Combined branch: opening `"`, then the `'` formula guard, then the value.
    let expected = format!(
        "aws-access-key,AWS Access Key,\"'=A1,B1\",high,AKIA****,{},{{}},filesystem,config/app.env,7,0,,,,unverifiable,0.9",
        hash_ab()
    );
    assert_eq!(out.lines().nth(1).expect("data row"), expected);
}

#[test]
fn csv_benign_leading_char_gets_no_guard_quote() {
    let mut f = base();
    f.location.file_path = Some("normal.env".into());
    let out = render(&[f]);
    let cols = data_columns(&out);
    assert_eq!(cols[8], "normal.env");
    assert!(
        !cols[8].starts_with('\''),
        "benign field must not gain a formula guard: {:?}",
        cols[8]
    );
}
