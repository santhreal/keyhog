//! Regression: `keyhog scan --stdin` (and the bare-`-` alias) drive the REAL
//! shipped binary over a piped stdin, the pre-commit / editor-save fast path.
//!
//! One secret is piped over stdin: a Slack **bot** token
//! (`xoxb-` + two numeric groups + a 24-char secret), which fires the
//! `slack-bot-token` detector (severity `critical`, service `slack`, name
//! "Slack Bot Token"). This token is used instead of a GitHub PAT because the
//! bot-token detector surfaces on the no-filename stdin chunk (`path: None`)
//! deterministically, whereas filename-context-sensitive detectors can score
//! differently without a path.
//!
//! Every format must surface THAT detector id off stdin:
//!   * json  -> a JSON ARRAY whose [0].detector_id is the id, with the exact
//!              source/file_path/line/offset/verification/confidence, and a
//!              credential_hash equal to sha256(token) verbatim.
//!   * sarif -> runs[0].results[0].ruleId is the id, level `error` (critical),
//!              exactly one result.
//!   * text  -> the "1 secret found" roll-up + "CRITICAL" label + detector
//!              name + the "stdin" location.
//!   * csv   -> the exact 20-field header, then a data row whose cells are the
//!              detector id/name/service/severity/redaction/hash/source in order.
//!
//! Negative twins: a clean stdin and an EMPTY stdin each exit 0 and produce the
//! format's honest empty shape (`[]`, header-only CSV, zero SARIF results, the
//! "No secrets detected" line).
//!
//! Every assertion pins a concrete value (exact bool / int / string / bytes /
//! exit code). None is a bare `!is_empty` / `is_ok`. Deterministic: one piped
//! secret, `--daemon=off`, `--backend cpu`.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// A Slack bot token proven (by running the shipped binary) to fire
/// `slack-bot-token` on its own bytes over stdin: `xoxb-` + `13`-digit +
/// `13`-digit + `24` alnum secret.
const TOKEN: &str = "xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx";

/// The detector id every format must carry for the piped secret.
const DETECTOR_ID: &str = "slack-bot-token";
/// The human-facing detector name (CSV column 2, text block).
const DETECTOR_NAME: &str = "Slack Bot Token";
/// SHA-256 of `TOKEN` (`credential_hash` is sha256(value)); verified out-of-band
/// with `printf '%s' <TOKEN> | sha256sum`.
const TOKEN_SHA256: &str = "a8dd917042994f6c6f183c6f0718ab4241065165b299050b51302d3167cc3901";
/// The redacted credential form the reporter emits for this token.
const REDACTED: &str = "xoxb...uvwx";
/// The exact 20-field CSV header the reporter writes (from `CsvReporter::new`).
const CSV_HEADER: &str = "detector_id,detector_name,service,severity,credential_redacted,credential_hash,companions_redacted,source,file_path,line,offset,commit,author,date,verification,confidence,entropy,remediation,metadata,additional_locations";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Run `keyhog scan --daemon=off --backend cpu --stdin --format <format>` with
/// `input` piped over stdin. Returns (exit code, stdout, stderr).
fn run_stdin(input: &[u8], format: &str) -> (Option<i32>, String, String) {
    run_stdin_args(
        input,
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--stdin",
            "--format",
            format,
        ],
    )
}

/// Run the binary with an explicit arg vector, piping `input` over stdin.
fn run_stdin_args(input: &[u8], args: &[&str]) -> (Option<i32>, String, String) {
    let mut child = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn keyhog scan --stdin");
    child
        .stdin
        .take()
        .expect("child stdin handle")
        .write_all(input)
        .expect("pipe input to stdin");
    let out = child.wait_with_output().expect("wait keyhog scan --stdin");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn parse_csv_row(row: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = row.chars().peekable();
    while let Some(ch) = chars.next() {
        if quoted {
            match ch {
                '"' if chars.peek() == Some(&'"') => {
                    field.push('"');
                    chars.next();
                }
                '"' => quoted = false,
                _ => field.push(ch),
            }
        } else {
            match ch {
                '"' if field.is_empty() => quoted = true,
                ',' => fields.push(std::mem::take(&mut field)),
                _ => field.push(ch),
            }
        }
    }
    fields.push(field);
    fields
}

/// A byte string with no credential-shaped content at all (a true negative
/// twin: avoids credential-bridge keywords secret/key/token/password/api).
const CLEAN_INPUT: &[u8] = b"just ordinary prose with plain everyday words here\n";

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// json off stdin: finding present -> exit 1, a JSON ARRAY (not an object)
/// whose single element carries the exact detector id.
#[test]
fn stdin_json_finding_surfaces_with_exact_detector_id_and_exit_1() {
    let input = format!("{TOKEN}\n");
    let (code, out, err) = run_stdin(input.as_bytes(), "json");
    assert_eq!(
        code,
        Some(1),
        "stdin json scan with a finding must exit 1; stderr={err}"
    );

    let v: serde_json::Value = serde_json::from_str(&out).expect("stdin json stdout must parse");
    let arr = v
        .as_array()
        .expect("stdin json report must be a top-level ARRAY");
    assert_eq!(
        arr.len(),
        1,
        "exactly one secret piped -> one json element, got {arr:?}"
    );
    assert_eq!(
        arr[0].get("detector_id").and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "stdin json[0].detector_id must be the piped detector id"
    );
}

/// json off stdin: the finding's identity and stdin-specific location fields are
/// exact (source `stdin`, NO file path, line 1, offset 0, verification skipped).
#[test]
fn stdin_json_exact_identity_and_location_fields() {
    let input = format!("{TOKEN}\n");
    let (_code, out, _err) = run_stdin(input.as_bytes(), "json");
    let v: serde_json::Value = serde_json::from_str(&out).expect("stdin json parse");
    let obj = &v.as_array().expect("array")[0];

    assert_eq!(
        obj.get("detector_name").and_then(|x| x.as_str()),
        Some(DETECTOR_NAME),
        "detector_name must be the human label"
    );
    assert_eq!(
        obj.get("service").and_then(|x| x.as_str()),
        Some("slack"),
        "service field must be `slack`"
    );
    assert_eq!(
        obj.get("severity").and_then(|x| x.as_str()),
        Some("critical"),
        "slack-bot-token is Critical -> kebab token `critical`"
    );
    assert_eq!(
        obj.pointer("/location/source").and_then(|x| x.as_str()),
        Some("stdin"),
        "location.source must be `stdin` for a piped scan"
    );
    assert_eq!(
        obj.pointer("/location/file_path"),
        Some(&serde_json::Value::Null),
        "a stdin chunk has NO file path -> location.file_path must be json null"
    );
    assert_eq!(
        obj.pointer("/location/line").and_then(|x| x.as_u64()),
        Some(1),
        "the single-line stdin payload reports line 1"
    );
    assert_eq!(
        obj.pointer("/location/offset").and_then(|x| x.as_u64()),
        Some(0),
        "the token starts at byte offset 0 of the piped chunk"
    );
    assert_eq!(
        obj.get("verification").and_then(|x| x.as_str()),
        Some("skipped"),
        "no live verification requested -> verification `skipped`"
    );
}

/// json off stdin: the credential is redacted (never raw) and the reported
/// credential_hash equals sha256(TOKEN) verbatim, proving the exact bytes are
/// hashed, not a truncated/salted variant.
#[test]
fn stdin_json_redacts_credential_and_hashes_exact_bytes() {
    let input = format!("{TOKEN}\n");
    let (_code, out, _err) = run_stdin(input.as_bytes(), "json");
    let v: serde_json::Value = serde_json::from_str(&out).expect("stdin json parse");
    let obj = &v.as_array().expect("array")[0];

    let redacted = obj
        .get("credential_redacted")
        .and_then(|x| x.as_str())
        .expect("credential_redacted present");
    assert_eq!(
        redacted, REDACTED,
        "the reported credential must be the masked form, not raw"
    );
    assert_ne!(
        redacted, TOKEN,
        "the raw token must never appear in credential_redacted"
    );
    assert_eq!(
        obj.get("credential_hash").and_then(|x| x.as_str()),
        Some(TOKEN_SHA256),
        "credential_hash must be sha256 of the exact piped token bytes"
    );
    assert_eq!(
        obj.get("confidence").and_then(|x| x.as_f64()),
        Some(0.9),
        "the reported confidence for this token is exactly 0.9"
    );
}

/// json negative twin: clean stdin exits 0 and the report is EXACTLY the two
/// bytes `[]`.
#[test]
fn stdin_json_clean_is_exactly_bracket_pair_exit_0() {
    let (code, out, err) = run_stdin(CLEAN_INPUT, "json");
    assert_eq!(
        code,
        Some(0),
        "clean stdin json scan must exit 0; stderr={err}"
    );
    assert_eq!(
        out.trim_end(),
        "[]",
        "clean stdin json must be exactly the bracket pair, got: {out:?}"
    );
}

/// json boundary: EMPTY stdin (zero bytes) is a valid clean scan -> exit 0 and
/// an empty array, not an error or hang.
#[test]
fn stdin_json_empty_input_exit_0_empty_array() {
    let (code, out, err) = run_stdin(b"", "json");
    assert_eq!(
        code,
        Some(0),
        "empty stdin must scan cleanly and exit 0; stderr={err}"
    );
    assert_eq!(
        out.trim_end(),
        "[]",
        "empty stdin json report must be the bracket pair, got: {out:?}"
    );
}

// ---------------------------------------------------------------------------
// SARIF
// ---------------------------------------------------------------------------

/// sarif off stdin: the single result's ruleId is the detector id, level is
/// `error` (critical maps to error), and there is exactly one result.
#[test]
fn stdin_sarif_ruleid_error_level_single_result() {
    let input = format!("{TOKEN}\n");
    let (code, out, err) = run_stdin(input.as_bytes(), "sarif");
    assert_eq!(
        code,
        Some(1),
        "stdin sarif scan with a finding must exit 1; stderr={err}"
    );
    let v: serde_json::Value = serde_json::from_str(&out).expect("stdin sarif must parse as JSON");
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
    assert_eq!(results.len(), 1, "one piped secret -> one SARIF result");
}

/// sarif negative twin: clean stdin exits 0 and produces ZERO results.
#[test]
fn stdin_sarif_clean_has_zero_results_exit_0() {
    let (code, out, err) = run_stdin(CLEAN_INPUT, "sarif");
    assert_eq!(
        code,
        Some(0),
        "clean stdin sarif scan must exit 0; stderr={err}"
    );
    let v: serde_json::Value = serde_json::from_str(&out).expect("sarif parse");
    let results = v
        .pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .expect("sarif results array must exist even when empty");
    assert_eq!(results.len(), 0, "clean stdin scan -> zero SARIF results");
}

// ---------------------------------------------------------------------------
// TEXT
// ---------------------------------------------------------------------------

/// text off stdin: the human roll-up names the count, the CRITICAL label, the
/// detector, and the `stdin` location.
#[test]
fn stdin_text_summary_labels_and_stdin_location() {
    let input = format!("{TOKEN}\n");
    let (code, out, err) = run_stdin(input.as_bytes(), "text");
    assert_eq!(
        code,
        Some(1),
        "stdin text scan with a finding must exit 1; stderr={err}"
    );
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
        "text block must name the detector 'Slack Bot Token', got:\n{combined}"
    );
    assert!(
        combined.contains("stdin"),
        "text block must report the 'stdin' location for a piped scan, got:\n{combined}"
    );
}

/// text negative twin: clean stdin exits 0 and prints the honest
/// "No secrets detected" line, never claiming the input is "clean".
#[test]
fn stdin_text_clean_honest_no_secrets_line_exit_0() {
    let (code, out, err) = run_stdin(CLEAN_INPUT, "text");
    assert_eq!(
        code,
        Some(0),
        "clean stdin text scan must exit 0; stderr={err}"
    );
    let combined = format!("{out}\n{err}");
    assert!(
        combined.contains("No secrets detected"),
        "clean stdin text scan must print the honest no-secrets line, got:\n{combined}"
    );
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// csv off stdin: the first line is EXACTLY the documented 20-field header, and
/// the sole data row's cells are id/name/service/severity/redaction/hash/source
/// in order, with exactly 20 fields.
#[test]
fn stdin_csv_header_and_single_data_row_exact_cells() {
    let input = format!("{TOKEN}\n");
    let (code, out, err) = run_stdin(input.as_bytes(), "csv");
    assert_eq!(
        code,
        Some(1),
        "stdin csv scan with a finding must exit 1; stderr={err}"
    );

    let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    let header = lines.first().expect("csv must have a header line");
    assert_eq!(
        header.trim_end(),
        CSV_HEADER,
        "csv header must be the exact documented field list in order"
    );

    let data: Vec<&str> = lines.iter().skip(1).copied().collect();
    assert_eq!(
        data.len(),
        1,
        "one piped secret -> exactly one csv data row"
    );
    let row = data[0];
    // id,name,service,severity,redacted,hash,source(stdin),file_path(empty)...
    let expected_prefix = format!(
        "{DETECTOR_ID},{DETECTOR_NAME},slack,critical,{REDACTED},{TOKEN_SHA256},{{}},stdin,,1,0,"
    );
    assert!(
        row.starts_with(&expected_prefix),
        "csv row must begin with id,name,service,severity,redacted,hash,stdin,(no path),line,offset; got:\n{row}\nwanted prefix:\n{expected_prefix}"
    );
    let fields = parse_csv_row(row);
    let field_count = fields.len();
    assert_eq!(
        field_count, 20,
        "csv data row must have exactly 20 fields, got {field_count}"
    );
    assert_eq!(fields[18], "{}");
    assert_eq!(fields[19], "[]");
}

/// csv negative twin: clean stdin exits 0 and emits ONLY the header.
#[test]
fn stdin_csv_clean_is_header_only_exit_0() {
    let (code, out, err) = run_stdin(CLEAN_INPUT, "csv");
    assert_eq!(
        code,
        Some(0),
        "clean stdin csv scan must exit 0; stderr={err}"
    );
    let lines: Vec<&str> = out.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "clean stdin csv must be header-only, got: {lines:?}"
    );
    assert_eq!(
        lines[0].trim_end(),
        CSV_HEADER,
        "the sole line must be the exact header"
    );
}

// ---------------------------------------------------------------------------
// BARE-DASH ALIAS + CROSS-FORMAT INVARIANTS
// ---------------------------------------------------------------------------

/// The bare `-` positional maps to `--stdin` (orchestrator arg rewrite): piping
/// the token with `scan ... -` (no `--stdin`) must produce the same finding and
/// exit 1.
#[test]
fn stdin_bare_dash_positional_aliases_to_stdin() {
    let input = format!("{TOKEN}\n");
    let (code, out, err) = run_stdin_args(
        input.as_bytes(),
        &[
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
            "-",
        ],
    );
    assert_eq!(
        code,
        Some(1),
        "bare `-` must be treated as --stdin and surface the finding (exit 1); stderr={err}"
    );
    let v: serde_json::Value = serde_json::from_str(&out).expect("bare-dash json parse");
    let arr = v.as_array().expect("array");
    assert_eq!(arr.len(), 1, "bare `-` stdin -> one finding");
    assert_eq!(
        arr[0].get("detector_id").and_then(|x| x.as_str()),
        Some(DETECTOR_ID),
        "bare `-` stdin must surface the slack-bot-token detector id"
    );
    assert_eq!(
        arr[0].pointer("/location/source").and_then(|x| x.as_str()),
        Some("stdin"),
        "bare `-` must scan as source `stdin`, not a filesystem path named '-'"
    );
}

/// Exit codes agree across all four stdin formats for the SAME piped finding:
/// all exit 1. A serializer dropping the finding on one path would break this.
#[test]
fn stdin_exit_codes_match_across_formats_with_finding() {
    let input = format!("{TOKEN}\n");
    let codes: Vec<Option<i32>> = ["json", "sarif", "text", "csv"]
        .iter()
        .map(|f| run_stdin(input.as_bytes(), f).0)
        .collect();
    assert_eq!(
        codes,
        vec![Some(1), Some(1), Some(1), Some(1)],
        "every stdin format must exit 1 for the same piped finding, got {codes:?}"
    );
}

/// Exit codes agree across all four stdin formats for clean input: all exit 0.
#[test]
fn stdin_exit_codes_match_across_formats_when_clean() {
    let codes: Vec<Option<i32>> = ["json", "sarif", "text", "csv"]
        .iter()
        .map(|f| run_stdin(CLEAN_INPUT, f).0)
        .collect();
    assert_eq!(
        codes,
        vec![Some(0), Some(0), Some(0), Some(0)],
        "every stdin format must exit 0 for clean input, got {codes:?}"
    );
}

/// The SAME detector id is surfaced by the json, sarif, and csv stdin paths for
/// the one piped secret (a per-format recall hole this catches).
#[test]
fn stdin_all_structured_formats_surface_same_detector_id() {
    let input = format!("{TOKEN}\n");

    let (_c1, json_out, _e1) = run_stdin(input.as_bytes(), "json");
    let jv: serde_json::Value = serde_json::from_str(&json_out).expect("json parse");
    let json_id = jv
        .as_array()
        .and_then(|a| a.first())
        .and_then(|o| o.get("detector_id"))
        .and_then(|x| x.as_str());

    let (_c2, sarif_out, _e2) = run_stdin(input.as_bytes(), "sarif");
    let sv: serde_json::Value = serde_json::from_str(&sarif_out).expect("sarif parse");
    let sarif_id = sv
        .pointer("/runs/0/results/0/ruleId")
        .and_then(|x| x.as_str());

    let (_c3, csv_out, _e3) = run_stdin(input.as_bytes(), "csv");
    let csv_id = csv_out
        .lines()
        .filter(|l| !l.is_empty())
        .nth(1)
        .and_then(|row| row.split(',').next());

    assert_eq!(json_id, Some(DETECTOR_ID), "json detector id off stdin");
    assert_eq!(sarif_id, Some(DETECTOR_ID), "sarif ruleId off stdin");
    assert_eq!(csv_id, Some(DETECTOR_ID), "csv first column off stdin");
}
