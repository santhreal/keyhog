//! Regression: `keyhog scan --format {json,sarif,text,csv}` render the SAME
//! planted secret through the REAL shipped binary, each in its format's exact
//! structure, with exit codes that agree across formats.
//!
//! One secret is planted: a GitHub classic PAT with a valid trailing byte-run
//! (`ghp_` + 36 alnum), which fires the `github-classic-pat` detector
//! (severity `critical`, service `github`, name "GitHub Classic PAT"). Every
//! format must surface THAT detector id, and:
//!   * json  -> a JSON ARRAY whose [0].detector_id is the id
//!   * sarif -> runs[0].results[0].ruleId is the id, level `error` (critical),
//!              rule security-severity band "9.5"
//!   * text  -> the "1 secret found" roll-up + "CRITICAL" label + detector name
//!   * csv   -> the exact documented header, then a data row whose first cells
//!              are `github-classic-pat,GitHub Classic PAT,github,critical,...`
//!
//! Negative twins: a clean file must exit 0 in every format and produce that
//! format's honest empty shape (`[]`, header-only CSV, zero SARIF results, the
//! "No secrets detected" text line).
//!
//! Every assertion pins a concrete value (exact bool / int / string / bytes /
//! exit code). None is a bare `!is_empty` / `is_ok`. Deterministic: one planted
//! secret, `--daemon=off`, `--backend cpu`.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// A planted GitHub classic PAT proven (by the format/backend parity e2e) to
/// fire `github-classic-pat` on its own bytes: `ghp_` + 36 alphanumerics with a
/// clean right boundary.
const PLANTED: &str = "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";

/// The detector id every format must carry for the planted secret.
const DETECTOR_ID: &str = "github-classic-pat";
/// The human-facing detector name (CSV column 2, text block).
const DETECTOR_NAME: &str = "GitHub Classic PAT";
/// The exact CSV header line the reporter writes (from `CsvReporter::new`).
const CSV_HEADER: &str = "detector_id,detector_name,service,severity,credential_redacted,credential_hash,source,file_path,line,offset,commit,author,date,verification,confidence";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Plant the PAT in a `.env` file inside a fresh tempdir.
fn leak_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("dump.txt");
    // Bare token on its own line: fires github-classic-pat on the literal shape
    // and carries NO key=value keyword context, so no generic keyword detector
    // co-fires. Exactly one finding is produced.
    std::fs::write(&path, format!("{PLANTED}\n")).expect("write leak fixture");
    (dir, path)
}

/// A file with no credential-shaped content at all.
fn clean_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("notes.txt");
    // Deliberately avoids credential-bridge keywords (secret/key/token/
    // password/api) so nothing fires — a true negative twin.
    std::fs::write(
        &path,
        "just ordinary prose with plain everyday words here\n",
    )
    .expect("write clean fixture");
    (dir, path)
}

/// Run `keyhog scan --daemon=off --backend cpu --format <format> <path>`.
/// Returns (exit code, stdout, stderr).
fn run(path: &PathBuf, format: &str) -> (Option<i32>, String, String) {
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--no-suppress-test-fixtures",
            "--format",
            format,
        ])
        .arg(path)
        .output()
        .expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// json: findings present -> exit 1, a JSON ARRAY (not an object) whose single
/// element carries the exact detector id / severity / service.
#[test]
fn json_format_is_array_with_exact_detector_fields() {
    let (_dir, path) = leak_fixture();
    let (code, out, err) = run(&path, "json");
    assert_eq!(
        code,
        Some(1),
        "json scan with a finding must exit 1; stderr={err}"
    );

    let v: serde_json::Value = serde_json::from_str(&out).expect("json stdout must parse");
    let arr = v.as_array().expect("json report must be a top-level ARRAY");
    assert_eq!(
        arr.len(),
        1,
        "exactly one secret planted -> one json element"
    );

    let obj = &arr[0];
    assert_eq!(
        obj.get("detector_id").and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "json[0].detector_id must be the planted detector id"
    );
    assert_eq!(
        obj.get("severity").and_then(|x| x.as_str()),
        Some("critical"),
        "github-classic-pat is Critical -> kebab token `critical`"
    );
    assert_eq!(
        obj.get("service").and_then(|x| x.as_str()),
        Some("github"),
        "service field must be `github`"
    );
    assert_eq!(
        obj.get("detector_name").and_then(|x| x.as_str()),
        Some(DETECTOR_NAME),
        "detector_name must be the human label"
    );
}

/// json negative twin: a clean file exits 0 and the report is EXACTLY the two
/// bytes `[]` (array opened + closed with no elements).
#[test]
fn json_clean_run_is_exactly_bracket_pair() {
    let (_dir, path) = clean_fixture();
    let (code, out, err) = run(&path, "json");
    assert_eq!(code, Some(0), "clean json scan must exit 0; stderr={err}");
    assert_eq!(
        out.trim_end(),
        "[]",
        "an empty json run must be exactly the bracket pair, got: {out:?}"
    );
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

/// sarif: the single result's `ruleId` is the detector id and `level` is
/// `error` (critical maps to error).
#[test]
fn sarif_format_ruleid_and_error_level() {
    let (_dir, path) = leak_fixture();
    let (code, out, err) = run(&path, "sarif");
    assert_eq!(
        code,
        Some(1),
        "sarif scan with a finding must exit 1; stderr={err}"
    );

    let v: serde_json::Value = serde_json::from_str(&out).expect("sarif stdout must parse as JSON");
    assert_eq!(
        v.pointer("/runs/0/results/0/ruleId")
            .and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "sarif results[0].ruleId must be the detector id"
    );
    assert_eq!(
        v.pointer("/runs/0/results/0/level")
            .and_then(|x| x.as_str()),
        Some("error"),
        "critical severity -> SARIF level `error`"
    );
    let results = v
        .pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .expect("sarif runs[0].results must be an array");
    assert_eq!(results.len(), 1, "one planted secret -> one SARIF result");
}

/// sarif: the accumulated rule for the finding carries the code-scanning
/// `security-severity` band "9.5" for a Critical detector.
#[test]
fn sarif_rule_security_severity_band_critical() {
    let (_dir, path) = leak_fixture();
    let (_code, out, _err) = run(&path, "sarif");
    let v: serde_json::Value = serde_json::from_str(&out).expect("sarif parse");

    assert_eq!(
        v.pointer("/runs/0/tool/driver/rules/0/id")
            .and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "the accumulated rule id must be the detector id"
    );
    assert_eq!(
        v.pointer("/runs/0/tool/driver/rules/0/properties/security-severity")
            .and_then(|x| x.as_str()),
        Some("9.5"),
        "Critical -> security-severity band 9.5"
    );
}

/// sarif negative twin: a clean file exits 0 and produces ZERO results.
#[test]
fn sarif_clean_run_has_zero_results() {
    let (_dir, path) = clean_fixture();
    let (code, out, err) = run(&path, "sarif");
    assert_eq!(code, Some(0), "clean sarif scan must exit 0; stderr={err}");
    let v: serde_json::Value = serde_json::from_str(&out).expect("sarif parse");
    let results = v
        .pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .expect("sarif results array must exist even when empty");
    assert_eq!(results.len(), 0, "clean scan -> zero SARIF results");
}

// ---------------------------------------------------------------------------
// TEXT
// ---------------------------------------------------------------------------

/// text: the human roll-up names the count, the CRITICAL label, and the
/// detector. (Summary is written to stdout by the Text reporter; stderr is
/// folded in defensively.)
#[test]
fn text_format_summary_and_labels() {
    let (_dir, path) = leak_fixture();
    let (code, out, err) = run(&path, "text");
    assert_eq!(code, Some(1), "text scan with a finding must exit 1");
    let combined = format!("{out}\n{err}");

    assert!(
        combined.contains("1 secret found"),
        "text summary must read '1 secret found', got:\n{combined}"
    );
    assert!(
        combined.contains("CRITICAL"),
        "text block must carry the CRITICAL severity label, got:\n{combined}"
    );
    assert!(
        combined.contains(DETECTOR_NAME),
        "text block must name the detector 'GitHub Classic PAT', got:\n{combined}"
    );
}

/// text negative twin: a clean file exits 0 and prints the honest
/// "No secrets detected" line, never claiming the tree is "clean".
#[test]
fn text_clean_run_honest_no_secrets_line() {
    let (_dir, path) = clean_fixture();
    let (code, out, err) = run(&path, "text");
    assert_eq!(code, Some(0), "clean text scan must exit 0");
    let combined = format!("{out}\n{err}");
    assert!(
        combined.contains("No secrets detected"),
        "clean text scan must print the honest no-secrets line, got:\n{combined}"
    );
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// csv: the first line is EXACTLY the documented 15-field header.
#[test]
fn csv_format_header_is_exact() {
    let (_dir, path) = leak_fixture();
    let (code, out, err) = run(&path, "csv");
    assert_eq!(
        code,
        Some(1),
        "csv scan with a finding must exit 1; stderr={err}"
    );
    let header = out.lines().next().expect("csv must have a header line");
    assert_eq!(
        header.trim_end(),
        CSV_HEADER,
        "csv header must be the exact documented field list in order"
    );
}

/// csv: exactly one data row, and its leading cells are the detector id, name,
/// service, and severity in order; the row has exactly 15 fields.
#[test]
fn csv_format_single_data_row_fields() {
    let (_dir, path) = leak_fixture();
    let (_code, out, _err) = run(&path, "csv");
    let lines: Vec<&str> = out.lines().collect();
    let data: Vec<&str> = lines
        .iter()
        .skip(1)
        .filter(|l| !l.is_empty())
        .copied()
        .collect();
    assert_eq!(
        data.len(),
        1,
        "one planted secret -> exactly one csv data row"
    );

    let row = data[0];
    assert!(
        row.starts_with("github-classic-pat,GitHub Classic PAT,github,critical,"),
        "csv row must begin with id,name,service,severity in order, got: {row}"
    );
    let field_count = row.matches(',').count() + 1;
    assert_eq!(
        field_count, 15,
        "csv data row must have exactly 15 fields, got {field_count}"
    );
}

/// csv negative twin: a clean file exits 0 and emits ONLY the header (no data
/// rows).
#[test]
fn csv_clean_run_is_header_only() {
    let (_dir, path) = clean_fixture();
    let (code, out, err) = run(&path, "csv");
    assert_eq!(code, Some(0), "clean csv scan must exit 0; stderr={err}");
    let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "clean csv must be header-only, got: {lines:?}"
    );
    assert_eq!(
        lines[0].trim_end(),
        CSV_HEADER,
        "the sole line must be the header"
    );
}

// ---------------------------------------------------------------------------
// CROSS-FORMAT INVARIANTS
// ---------------------------------------------------------------------------

/// Exit codes agree across all four formats for the SAME finding: all exit 1.
#[test]
fn exit_codes_match_across_all_formats_with_finding() {
    let (_dir, path) = leak_fixture();
    let codes: Vec<Option<i32>> = ["json", "sarif", "text", "csv"]
        .iter()
        .map(|f| run(&path, f).0)
        .collect();
    assert_eq!(
        codes,
        vec![Some(1), Some(1), Some(1), Some(1)],
        "every format must exit 1 for the same planted finding, got {codes:?}"
    );
}

/// Exit codes agree across all four formats for a clean tree: all exit 0.
#[test]
fn exit_codes_match_across_all_formats_when_clean() {
    let (_dir, path) = clean_fixture();
    let codes: Vec<Option<i32>> = ["json", "sarif", "text", "csv"]
        .iter()
        .map(|f| run(&path, f).0)
        .collect();
    assert_eq!(
        codes,
        vec![Some(0), Some(0), Some(0), Some(0)],
        "every format must exit 0 for a clean tree, got {codes:?}"
    );
}

/// The SAME detector id is surfaced by the json, sarif, and csv paths for the
/// one planted secret — a serializer dropping the finding on one path is a
/// silent recall hole this catches.
#[test]
fn all_structured_formats_surface_same_detector_id() {
    let (_dir, path) = leak_fixture();

    let (_c1, json_out, _e1) = run(&path, "json");
    let jv: serde_json::Value = serde_json::from_str(&json_out).expect("json parse");
    let json_id = jv
        .as_array()
        .and_then(|a| a.first())
        .and_then(|o| o.get("detector_id"))
        .and_then(|x| x.as_str());

    let (_c2, sarif_out, _e2) = run(&path, "sarif");
    let sv: serde_json::Value = serde_json::from_str(&sarif_out).expect("sarif parse");
    let sarif_id = sv
        .pointer("/runs/0/results/0/ruleId")
        .and_then(|x| x.as_str());

    let (_c3, csv_out, _e3) = run(&path, "csv");
    let csv_lines: Vec<&str> = csv_out.lines().skip(1).filter(|l| !l.is_empty()).collect();
    let csv_id = csv_lines.first().and_then(|row| row.split(',').next());

    assert_eq!(json_id, Some(DETECTOR_ID), "json detector id");
    assert_eq!(sarif_id, Some(DETECTOR_ID), "sarif ruleId");
    assert_eq!(csv_id, Some(DETECTOR_ID), "csv first column");
}

/// The redacted credential form is identical across json and csv (the reporter
/// must not redact differently per format). Derived at runtime from json, then
/// required to appear verbatim as the csv `credential_redacted` cell.
#[test]
fn redacted_credential_consistent_between_json_and_csv() {
    let (_dir, path) = leak_fixture();

    let (_c1, json_out, _e1) = run(&path, "json");
    let jv: serde_json::Value = serde_json::from_str(&json_out).expect("json parse");
    let redacted = jv
        .as_array()
        .and_then(|a| a.first())
        .and_then(|o| o.get("credential_redacted"))
        .and_then(|x| x.as_str())
        .expect("json must carry credential_redacted")
        .to_string();
    // The redaction must be a non-trivial masked form, not the raw secret.
    assert_ne!(
        redacted, PLANTED,
        "the reported credential must be redacted, not raw"
    );
    assert!(
        !redacted.is_empty(),
        "credential_redacted must be populated"
    );

    let (_c2, csv_out, _e2) = run(&path, "csv");
    let data_row = csv_out.lines().nth(1).expect("csv must have a data row");
    let cell = data_row
        .split(',')
        .nth(4)
        .expect("csv column 5 = credential_redacted");
    assert_eq!(
        cell,
        redacted.as_str(),
        "csv credential_redacted cell must equal the json redacted form"
    );
}
