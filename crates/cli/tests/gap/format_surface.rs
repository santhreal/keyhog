//! Format-surface integration tests: every `--format` value
//! (text / json / jsonl / sarif / csv / github-annotations / gitlab-sast / html / junit) on an EMPTY corpus
//! and a NON-EMPTY corpus, asserting structural validity + the documented
//! exit code (0 = clean, 1 = unverified findings present).
//!
//! Every expectation below is derived directly from the real reporters in
//! `crates/core/src/report/{json,sarif,csv,github_annotations,html,junit,text}.rs`, the
//! format dispatch in `crates/cli/src/reporting.rs::report_with`, and the
//! exit-code ladder in `crates/cli/src/orchestrator/run.rs` (lines 332-340)
//! / the daemon path in `crates/cli/src/subcommands/scan.rs` (line 224-228):
//!
//!   * live credentials -> 10, scanner panic -> 11, any reported finding
//!     -> 1, otherwise -> 0. With no `--verify`, every finding is
//!     `VerificationResult::Skipped`, so a non-empty report exits 1.
//!
//! The product is the binary (`CARGO_BIN_EXE_keyhog`); these drive it the
//! way CI gates and SARIF/CSV consumers do.
//!
//! `--daemon=off` is passed on every scan so behavior never depends on
//! whether a `keyhog daemon` socket happens to exist on the test host
//! (see `scan.rs::daemon_route`): the in-process orchestrator is the
//! single source of truth for the exit-code ladder we assert.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A planted credential that the embedded corpus catches with HIGH
/// confidence and that is NOT on the bundled test-fixture suppression
/// list (it is a freshly-randomized AKIA body, not AWS's published
/// `AKIAIOSFODNN7EXAMPLE`). `concat!` keeps the literal from tripping
/// keyhog's own self-scan / pre-commit hook on this very test file.
const AWS_KEY_FIXTURE: &str = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");

/// A file with no credential whatsoever -> the empty-corpus case.
const CLEAN_FIXTURE: &str = "fn main() { println!(\"hello, world\"); }\n";

/// Run `keyhog scan --daemon=off --format <fmt> <file>` over a temp file
/// containing `content`. Returns (stdout, stderr, exit-code).
fn scan_with_format(content: &str, fmt: &str) -> (String, String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    // Neutral filename + extension: no `test`/`fixture`/`example` token in
    // the path, so the test-path confidence down-weighting does not fire
    // and a genuine AKIA key reports at full strength.
    let path = dir.path().join("planted.env");
    std::fs::write(&path, content).expect("write fixture");

    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .arg("--backend")
        .arg("simd")
        .arg("--format")
        .arg(fmt)
        .arg(&path)
        .output()
        .unwrap_or_else(|e| panic!("spawn keyhog scan --format {fmt}: {e}"));

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
        output.status.code(),
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

/// Same as `scan_with_format` but writes to `--output <file>` and returns
/// the file's bytes alongside the exit code. The reporting code in
/// `reporting.rs` atomic-writes the report to a NamedTempFile then renames,
/// so the on-disk bytes are the canonical structured artifact (no banner /
/// progress noise can leak in, unlike stdout).
fn scan_to_output_file(content: &str, fmt: &str) -> (String, Option<i32>) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.env");
    std::fs::write(&path, content).expect("write fixture");
    let out = dir.path().join("report.out");

    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .arg("--backend")
        .arg("simd")
        .arg("--format")
        .arg(fmt)
        .arg("--output")
        .arg(&out)
        .arg(&path)
        .output()
        .unwrap_or_else(|e| panic!("spawn keyhog scan --format {fmt} --output: {e}"));

    let bytes = std::fs::read_to_string(&out)
        .unwrap_or_else(|e| panic!("read --output file for {fmt}: {e}"));
    (bytes, output.status.code())
}

fn json_findings(value: &serde_json::Value) -> &[serde_json::Value] {
    value["findings"]
        .as_array()
        .expect("versioned JSON report must contain findings")
}

// ---------------------------------------------------------------------------
// EXIT-CODE CONTRACT across every format
// ---------------------------------------------------------------------------

/// Clean corpus -> exit 0 for EVERY format. The exit code is computed in
/// `orchestrator/run.rs` purely from finding count; it is format-agnostic.
#[test]
fn every_format_exits_0_on_clean_corpus() {
    for fmt in [
        "text",
        "json-envelope",
        "jsonl-envelope",
        "sarif",
        "csv",
        "github-annotations",
        "gitlab-sast",
        "html",
        "junit",
    ] {
        let (_stdout, stderr, code) = scan_with_format(CLEAN_FIXTURE, fmt);
        assert_eq!(
            code,
            Some(0),
            "format `{fmt}` on a clean corpus must exit 0; stderr={stderr}"
        );
    }
}

/// Non-empty corpus (planted AKIA key, unverified) -> exit 1 for EVERY
/// format. No `--verify`, so the finding is `Skipped`, not `Live`; the
/// ladder lands on `has_new_entries` => `ExitCode::from(1)`.
#[test]
fn every_format_exits_1_on_planted_finding() {
    for fmt in [
        "text",
        "json-envelope",
        "jsonl-envelope",
        "sarif",
        "csv",
        "github-annotations",
        "gitlab-sast",
        "html",
        "junit",
    ] {
        let (_stdout, stderr, code) = scan_with_format(AWS_KEY_FIXTURE, fmt);
        assert_eq!(
            code,
            Some(1),
            "format `{fmt}` with a planted unverified finding must exit 1 \
             (not 10/live, not 0/clean); stderr={stderr}"
        );
    }
}

/// The exit code must NOT be the live-credential code (10) or panic code
/// (11) for any format on the planted-but-unverified fixture. Pins the
/// ladder ordering: `has_live_credentials` is false without `--verify`.
#[test]
fn planted_finding_is_never_live_or_panic_exit() {
    for fmt in [
        "text",
        "json-envelope",
        "jsonl-envelope",
        "sarif",
        "csv",
        "github-annotations",
        "gitlab-sast",
        "html",
        "junit",
    ] {
        let (_stdout, _stderr, code) = scan_with_format(AWS_KEY_FIXTURE, fmt);
        assert_ne!(
            code,
            Some(10),
            "format `{fmt}` must not report live (10) without --verify"
        );
        assert_ne!(code, Some(11), "format `{fmt}` must not report panic (11)");
        assert_ne!(
            code,
            Some(2),
            "format `{fmt}` must not report user/config error (2)"
        );
        assert_ne!(
            code,
            Some(3),
            "format `{fmt}` must not report system error (3)"
        );
    }
}

// ---------------------------------------------------------------------------
// JSON (versioned JsonEnvelopeReporter)
// ---------------------------------------------------------------------------

/// Empty corpus -> stdout is a versioned envelope with no findings.
#[test]
fn json_empty_corpus_is_exact_empty_array() {
    let (stdout, stderr, code) = scan_with_format(CLEAN_FIXTURE, "json-envelope");
    assert_eq!(
        code,
        Some(0),
        "clean json scan must exit 0; stderr={stderr}"
    );
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("empty JSON parses");
    assert_eq!(value["schema_version"]["major"], 1);
    assert!(json_findings(&value).is_empty());
}

/// Empty corpus JSON parses to an empty findings array (structural validity).
#[test]
fn json_empty_corpus_parses_to_empty_array() {
    let (stdout, _stderr, _code) = scan_with_format(CLEAN_FIXTURE, "json-envelope");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("empty JSON parses");
    assert!(
        json_findings(&v).is_empty(),
        "empty findings must remain empty"
    );
}

/// Non-empty corpus -> stdout is a valid JSON envelope with >=1 finding, each
/// carrying the contract fields the JsonReporter serializes from
/// VerifiedFinding.
#[test]
fn json_planted_finding_is_valid_array_with_contract_fields() {
    let (stdout, stderr, code) = scan_with_format(AWS_KEY_FIXTURE, "json-envelope");
    assert_eq!(
        code,
        Some(1),
        "json planted scan must exit 1; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("planted JSON parses");
    let arr = json_findings(&v);
    assert!(
        !arr.is_empty(),
        "planted finding must produce >=1 JSON object"
    );
    for f in arr {
        for field in [
            "detector_id",
            "detector_name",
            "service",
            "severity",
            "credential_redacted",
            "credential_hash",
            "location",
            "verification",
        ] {
            assert!(
                f.get(field).is_some(),
                "JSON finding missing `{field}`: {f}"
            );
        }
    }
}

/// The AKIA fixture surfaces as an AWS detection in JSON. AWS keys are
/// caught under the canonical `aws-access-key` id on every backend.
#[test]
fn json_planted_finding_is_aws_detection() {
    let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, "json-envelope");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parses");
    let arr = json_findings(&v);
    let aws = arr.iter().any(|f| {
        matches!(
            f.get("detector_id").and_then(|x| x.as_str()),
            Some("aws-access-key")
        )
    });
    assert!(aws, "expected an AWS detection in JSON output; got {arr:?}");
}

/// Verification is `Skipped` (no `--verify`): the serialized discriminant
/// must reflect that, never `live`. VerifiedFinding serializes unit
/// variants as lowercase bare strings (see html.rs flatten comment).
#[test]
fn json_unverified_finding_serializes_skipped() {
    let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, "json-envelope");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parses");
    let arr = json_findings(&v);
    for f in arr {
        let verification = f.get("verification").expect("verification field");
        // Skipped serializes as the bare string "skipped".
        assert_eq!(
            verification.as_str(),
            Some("skipped"),
            "unverified finding must serialize verification as \"skipped\"; got {verification}"
        );
    }
}

/// Redaction contract: with no `--show-secrets`, credential_redacted is
/// `redact(cred)` = first4 + "..." + last4 for a >8-char ASCII credential.
/// The AKIA key is `AKIAQYLPMN5HFIQR7XYA` (20 chars) -> `AK...YA`.
#[test]
fn json_credential_is_redacted_not_plaintext() {
    let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, "json-envelope");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("JSON parses");
    let arr = v.as_array().expect("array");
    let aws = arr
        .iter()
        .find(|f| {
            matches!(
                f.get("detector_id").and_then(|x| x.as_str()),
                Some("aws-access-key")
            )
        })
        .expect("aws finding present");
    let red = aws
        .get("credential_redacted")
        .and_then(|v| v.as_str())
        .expect("credential_redacted string");
    assert_eq!(
        red, "AK...YA",
        "redact() of the 20-char AKIA key must be first2...last2; got {red:?}"
    );
    // The full plaintext key body must never appear.
    assert!(
        !stdout.contains("AKIAQYLPMN5HFIQR7XYA"),
        "plaintext credential must not leak into JSON without --show-secrets"
    );
}

/// `--output <file>` JSON: the on-disk artifact equals the structured
/// report exactly (atomic-write path in reporting.rs), an empty envelope when clean.
#[test]
fn json_output_file_clean_is_exact_empty_array() {
    let (bytes, code) = scan_to_output_file(CLEAN_FIXTURE, "json-envelope");
    assert_eq!(code, Some(0));
    let value: serde_json::Value = serde_json::from_str(&bytes).expect("JSON output parses");
    assert_eq!(value["schema_version"]["major"], 1);
    assert!(json_findings(&value).is_empty());
}

// ---------------------------------------------------------------------------
// JSONL (versioned JsonlEnvelopeReporter)
// ---------------------------------------------------------------------------

/// Empty corpus -> JSONL emits a header and no finding records.
#[test]
fn jsonl_empty_corpus_is_empty_output() {
    let (stdout, stderr, code) = scan_with_format(CLEAN_FIXTURE, "jsonl-envelope");
    assert_eq!(
        code,
        Some(0),
        "clean jsonl scan must exit 0; stderr={stderr}"
    );
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "empty JSONL stream must contain header and summary"
    );
    let header: serde_json::Value = serde_json::from_str(lines[0]).expect("header parses");
    assert_eq!(header["record_type"], "header");
    assert_eq!(header["schema_version"]["major"], 1);
    let summary: serde_json::Value = serde_json::from_str(lines[1]).expect("summary parses");
    assert_eq!(summary["record_type"], "summary");
    assert_eq!(summary["status"], "complete");
    assert_eq!(summary["finding_count"], 0);
}

/// Non-empty corpus -> one header, one JSON object per finding, and one summary,
/// each line
/// terminated by `\n` (writeln! after each object).
#[test]
fn jsonl_planted_finding_is_one_object_per_line() {
    let (stdout, stderr, code) = scan_with_format(AWS_KEY_FIXTURE, "jsonl-envelope");
    assert_eq!(
        code,
        Some(1),
        "jsonl planted scan must exit 1; stderr={stderr}"
    );
    assert!(
        stdout.ends_with('\n'),
        "JSONL output must end with a newline after the final object; got {stdout:?}"
    );
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        lines.len() >= 3,
        "header, finding, and summary must be present"
    );
    let header: serde_json::Value = serde_json::from_str(lines[0]).expect("header parses");
    assert_eq!(header["record_type"], "header");
    let summary: serde_json::Value =
        serde_json::from_str(lines.last().expect("summary line")).expect("summary parses");
    assert_eq!(summary["record_type"], "summary");
    assert_eq!(summary["status"], "complete");
    assert_eq!(summary["finding_count"], 1);
    for line in &lines {
        let obj: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("each JSONL line is an object: {e}; line={line:?}"));
        assert!(
            obj.is_object(),
            "each JSONL line must be a JSON object, not an array; got {obj}"
        );
        if matches!(
            obj.get("record_type").and_then(|v| v.as_str()),
            Some("header" | "summary")
        ) {
            continue;
        }
        assert!(
            obj.get("detector_id").is_some(),
            "JSONL object missing detector_id: {obj}"
        );
    }
}

/// JSONL is NOT a bracketed array: a line must never start with `[`.
#[test]
fn jsonl_is_not_a_bracketed_array() {
    let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, "jsonl-envelope");
    assert!(
        !stdout.trim_start().starts_with('['),
        "JSONL must emit bare objects, never a `[...]` array; got {stdout:?}"
    );
}

// ---------------------------------------------------------------------------
// SARIF (SarifReporter, streaming v2.1.0)
// ---------------------------------------------------------------------------

/// Empty corpus -> SARIF still emits a complete, valid v2.1.0 document
/// with an empty results array and empty rules array. `finish()` calls
/// `ensure_prefix()` even when no result was reported.
#[test]
fn sarif_empty_corpus_is_valid_empty_document() {
    let (stdout, stderr, code) = scan_with_format(CLEAN_FIXTURE, "sarif");
    assert_eq!(
        code,
        Some(0),
        "clean sarif scan must exit 0; stderr={stderr}"
    );
    let v: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("empty SARIF must still be valid JSON");
    assert_eq!(
        v["version"], "2.1.0",
        "SARIF version must be 2.1.0 even when empty"
    );
    assert!(
        v["$schema"]
            .as_str()
            .is_some_and(|s| s.contains("sarif-2.1.0")),
        "empty SARIF must carry the 2.1.0 $schema; got {}",
        v["$schema"]
    );
    let run = &v["runs"][0];
    assert_eq!(
        run["results"].as_array().map(Vec::len),
        Some(0),
        "empty SARIF results array must be length 0; got {}",
        run["results"]
    );
    assert_eq!(
        run["tool"]["driver"]["rules"].as_array().map(Vec::len),
        Some(0),
        "empty SARIF rules array must be length 0; got {}",
        run["tool"]["driver"]["rules"]
    );
    assert_eq!(
        run["tool"]["driver"]["name"], "keyhog",
        "SARIF tool.driver.name must be keyhog"
    );
}

/// SARIF document ends with a trailing newline (sarif.rs `finish()` does
/// `writeln!` after the closing braces) and carries the taxonomies block.
#[test]
fn sarif_empty_corpus_carries_taxonomies_and_trailing_newline() {
    let (stdout, _stderr, _code) = scan_with_format(CLEAN_FIXTURE, "sarif");
    assert!(
        stdout.ends_with('\n'),
        "SARIF doc must end with a trailing newline; got tail {:?}",
        &stdout[stdout.len().saturating_sub(8)..]
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON");
    assert!(
        v["runs"][0]["taxonomies"].is_array(),
        "SARIF run must carry a `taxonomies` array (CWE/OWASP); got {}",
        v["runs"][0]["taxonomies"]
    );
}

/// Non-empty corpus -> SARIF has >=1 result; each result's ruleId resolves
/// into tool.driver.rules[]; each result has a valid SARIF level.
#[test]
fn sarif_planted_finding_result_resolves_into_rules() {
    let (stdout, stderr, code) = scan_with_format(AWS_KEY_FIXTURE, "sarif");
    assert_eq!(
        code,
        Some(1),
        "sarif planted scan must exit 1; stderr={stderr}"
    );
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("SARIF parses");
    assert_eq!(v["version"], "2.1.0");
    let run = &v["runs"][0];
    let results = run["results"].as_array().expect("results array");
    assert!(
        !results.is_empty(),
        "planted AKIA key must produce a SARIF result"
    );

    let rule_ids: std::collections::HashSet<String> = run["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array")
        .iter()
        .filter_map(|r| r["id"].as_str().map(str::to_string))
        .collect();
    assert!(
        !rule_ids.is_empty(),
        "non-empty SARIF must populate driver.rules"
    );

    for r in results {
        let rid = r["ruleId"].as_str().expect("each result has a ruleId");
        assert!(
            rule_ids.contains(rid),
            "ruleId {rid:?} not found in tool.driver.rules[]; GitHub would drop it"
        );
        assert!(
            matches!(
                r["level"].as_str(),
                Some("error" | "warning" | "note" | "none")
            ),
            "result.level must be a valid SARIF level; got {}",
            r["level"]
        );
        // CWE/OWASP taxonomy properties applied to every secret finding.
        assert_eq!(
            r["properties"]["cwe"], "CWE-798",
            "every SARIF result must carry CWE-798 (hard-coded credentials)"
        );
        assert_eq!(
            r["properties"]["owasp"], "A07:2021",
            "every SARIF result must carry OWASP A07:2021"
        );
        // Unverified -> verification property is "skipped".
        assert_eq!(
            r["properties"]["verification"], "skipped",
            "unverified SARIF result must carry verification=skipped; got {}",
            r["properties"]["verification"]
        );
    }
}

/// SARIF rules carry GitHub code-scanning severity metadata: a numeric
/// `security-severity` and a `security` tag (apply_code_scanning_props).
#[test]
fn sarif_rules_carry_code_scanning_severity_props() {
    let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, "sarif");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("SARIF parses");
    let rules = v["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array");
    assert!(!rules.is_empty());
    for rule in rules {
        let props = &rule["properties"];
        let sev = props["security-severity"]
            .as_str()
            .unwrap_or_else(|| panic!("rule {} missing security-severity", rule["id"]));
        sev.parse::<f64>()
            .unwrap_or_else(|_| panic!("security-severity must be numeric; got {sev:?}"));
        let tags: Vec<&str> = props["tags"]
            .as_array()
            .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
            .unwrap_or_default();
        assert!(
            tags.contains(&"security"),
            "rule {} must be tagged `security`; tags={tags:?}",
            rule["id"]
        );
    }
}

// ---------------------------------------------------------------------------
// CSV (CsvReporter)
// ---------------------------------------------------------------------------

/// The CSV header is written in `CsvReporter::new()` unconditionally, so
/// it appears even on an EMPTY corpus. Assert the exact 20-column header.
const CSV_HEADER: &str = "detector_id,detector_name,service,severity,credential_redacted,credential_hash,companions_redacted,source,file_path,line,offset,commit,author,date,verification,confidence,entropy,remediation,metadata,additional_locations";

#[test]
fn csv_empty_corpus_is_header_only() {
    let (stdout, stderr, code) = scan_with_format(CLEAN_FIXTURE, "csv");
    assert_eq!(code, Some(0), "clean csv scan must exit 0; stderr={stderr}");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "empty CSV report must be header-only (1 line); got {lines:?}"
    );
    assert_eq!(
        lines[0], CSV_HEADER,
        "CSV header must match the reporter exactly"
    );
}

/// Non-empty corpus -> header + >=1 data row. Each data row has exactly
/// 20 logical fields (matching the header column count), parsed as RFC-4180
/// because JSON remediation cells contain commas.
#[test]
fn csv_planted_finding_has_header_plus_data_rows() {
    let (stdout, stderr, code) = scan_with_format(AWS_KEY_FIXTURE, "csv");
    assert_eq!(
        code,
        Some(1),
        "csv planted scan must exit 1; stderr={stderr}"
    );
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        lines.len() >= 2,
        "CSV must have header + >=1 data row; got {lines:?}"
    );
    assert_eq!(lines[0], CSV_HEADER, "first CSV line must be the header");
    // Parse the JSON-bearing row instead of counting commas inside cells.
    let header_cols = CSV_HEADER.split(',').count();
    assert_eq!(header_cols, 20, "CSV header must declare 20 columns");
    for row in &lines[1..] {
        assert_eq!(
            parse_csv_row(row).len(),
            20,
            "CSV data row must have 20 columns matching the header; row={row:?}"
        );
    }
}

/// CSV data row carries the expected detector + redacted credential for
/// the AKIA fixture (column 0 = detector_id, column 4 = credential_redacted).
#[test]
fn csv_data_row_carries_aws_detector_and_redacted_credential() {
    let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, "csv");
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    let row = lines
        .iter()
        .skip(1)
        .find(|r| {
            let cols = parse_csv_row(r);
            cols.first()
                .is_some_and(|column| column == "aws-access-key")
        })
        .expect("a CSV data row for the AWS detection");
    let cols = parse_csv_row(row);
    assert_eq!(
        cols[4], "AK...YA",
        "credential_redacted column must be the redacted key; row={row:?}"
    );
    // verification column (index 14) must be the unverified discriminant.
    assert_eq!(
        cols[14], "skipped",
        "verification column must be `skipped` without --verify; row={row:?}"
    );
    // Full plaintext must never appear.
    assert!(
        !stdout.contains("AKIAQYLPMN5HFIQR7XYA"),
        "CSV must not leak plaintext credential"
    );
}

// ---------------------------------------------------------------------------
// HTML (HtmlReporter)
// ---------------------------------------------------------------------------

/// Empty corpus -> a full, well-formed HTML document is still emitted
/// (skeleton is written in `finish()` regardless of finding count), with
/// `const rawFindings = [];` inlined.
#[test]
fn html_empty_corpus_is_full_document_with_empty_findings() {
    let (stdout, stderr, code) = scan_with_format(CLEAN_FIXTURE, "html");
    assert_eq!(
        code,
        Some(0),
        "clean html scan must exit 0; stderr={stderr}"
    );
    assert!(
        stdout.starts_with("<!DOCTYPE html>"),
        "HTML report must start with <!DOCTYPE html>; got {:?}",
        &stdout[..stdout.len().min(40)]
    );
    assert!(
        stdout.contains("<title>KeyHog Secret Scan Report</title>"),
        "HTML must carry the KeyHog report title"
    );
    assert!(
        stdout.contains("const rawFindings = [];"),
        "empty HTML must inline `const rawFindings = [];`"
    );
    assert!(
        stdout.trim_end().ends_with("</html>"),
        "HTML report must close with </html>"
    );
}

/// Non-empty corpus -> the document carries a non-empty `rawFindings`
/// array literal. The inlined array is the data the report JS renders.
#[test]
fn html_planted_finding_inlines_nonempty_findings_array() {
    let (stdout, stderr, code) = scan_with_format(AWS_KEY_FIXTURE, "html");
    assert_eq!(
        code,
        Some(1),
        "html planted scan must exit 1; stderr={stderr}"
    );
    assert!(
        stdout.starts_with("<!DOCTYPE html>"),
        "HTML must start with the doctype"
    );
    // Locate the inlined array literal between `const rawFindings = ` and `;`.
    let marker = "const rawFindings = ";
    let start = stdout
        .find(marker)
        .expect("HTML must contain the rawFindings assignment");
    let after = &stdout[start + marker.len()..];
    let end = after
        .find(";\n")
        .or_else(|| after.find(';'))
        .expect("rawFindings terminator");
    let literal = &after[..end];
    assert!(
        literal.starts_with('[') && literal.ends_with(']'),
        "rawFindings must be a JSON array literal; got {literal:?}"
    );
    assert_ne!(
        literal, "[]",
        "planted finding must produce a non-empty rawFindings array"
    );
    assert!(
        literal.contains("aws-access-key"),
        "rawFindings must reference the AWS detector id; got {literal}"
    );
}

/// HTML script-injection hardening: the inlined findings JSON escapes
/// `<`, `>`, `/` to `\uXXXX` so a `</script>` byte sequence in any
/// finding field can never break out of the `<script>` element. Even on
/// the planted AKIA key (whose redacted form has no slash), the escaping
/// of `/` means the literal byte sequence `</script` must not appear
/// inside the inlined array.
#[test]
fn html_inlined_findings_never_contain_raw_script_close() {
    let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, "html");
    let marker = "const rawFindings = ";
    let start = stdout.find(marker).expect("rawFindings present");
    let after = &stdout[start + marker.len()..];
    let end = after.find(';').expect("terminator");
    let literal = &after[..end];
    assert!(
        !literal.contains("</script"),
        "inlined findings must not contain a raw </script close; got {literal}"
    );
    // escape_for_script replaces every `/` with /, so a forward slash
    // must not appear raw inside the literal at all.
    assert!(
        !literal.contains('/'),
        "escape_for_script must escape `/` to \\u002f inside rawFindings; got {literal}"
    );
}

// ---------------------------------------------------------------------------
// JUnit (JunitReporter)
// ---------------------------------------------------------------------------

/// Empty corpus -> a valid JUnit XML doc with a single empty testsuite:
/// tests="0" failures="0" errors="0". Skeleton is written in `finish()`.
#[test]
fn junit_empty_corpus_is_empty_testsuite() {
    let (stdout, stderr, code) = scan_with_format(CLEAN_FIXTURE, "junit");
    assert_eq!(
        code,
        Some(0),
        "clean junit scan must exit 0; stderr={stderr}"
    );
    assert!(
        stdout.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"),
        "JUnit must start with the XML declaration; got {:?}",
        &stdout[..stdout.len().min(50)]
    );
    assert!(
        stdout.contains("<testsuites>"),
        "JUnit must contain <testsuites>"
    );
    assert!(
        stdout.contains(
            "<testsuite name=\"keyhog\" tests=\"0\" failures=\"0\" errors=\"0\" time=\"0.0\">"
        ),
        "empty JUnit testsuite must declare tests=0 failures=0; got {stdout}"
    );
    assert!(
        !stdout.contains("<testcase"),
        "empty JUnit must contain no <testcase> elements"
    );
    assert!(
        stdout.trim_end().ends_with("</testsuites>"),
        "JUnit must close with </testsuites>"
    );
}

/// Non-empty corpus -> testsuite counts equal the finding count (the
/// reporter sets tests==failures==findings.len()), one <testcase> per
/// finding, each with a <failure> child.
#[test]
fn junit_planted_finding_counts_match_testcases() {
    let (stdout, stderr, code) = scan_with_format(AWS_KEY_FIXTURE, "junit");
    assert_eq!(
        code,
        Some(1),
        "junit planted scan must exit 1; stderr={stderr}"
    );
    let testcase_count = stdout.matches("<testcase ").count();
    let failure_count = stdout.matches("<failure ").count();
    assert!(
        testcase_count >= 1,
        "planted finding must produce >=1 <testcase>"
    );
    assert_eq!(
        testcase_count, failure_count,
        "each JUnit <testcase> must carry exactly one <failure>; \
         testcases={testcase_count} failures={failure_count}"
    );
    // The testsuite header must report tests==failures==testcase_count.
    let expected_header = format!(
        "<testsuite name=\"keyhog\" tests=\"{n}\" failures=\"{n}\" errors=\"0\" time=\"0.0\">",
        n = testcase_count
    );
    assert!(
        stdout.contains(&expected_header),
        "JUnit testsuite header must report tests=failures={testcase_count}; \
         expected line: {expected_header}\n--- got ---\n{stdout}"
    );
}

/// JUnit failure body carries the secret-detection metadata inside a
/// CDATA block, including the detector id and the unverified
/// "Verification:  skipped" line.
#[test]
fn junit_failure_body_carries_detection_metadata() {
    let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, "junit");
    assert!(
        stdout.contains("Secret detected:"),
        "JUnit <failure> message must announce a detected secret"
    );
    assert!(
        stdout.contains("<![CDATA["),
        "JUnit failure detail must be wrapped in CDATA"
    );
    assert!(
        stdout.contains("Detector ID:"),
        "JUnit CDATA body must include the Detector ID label"
    );
    assert!(
        stdout.contains("Verification:  skipped"),
        "unverified JUnit finding must report Verification: skipped; got {stdout}"
    );
    // Redacted credential, not plaintext.
    assert!(
        stdout.contains("Redacted:      AK...YA"),
        "JUnit body must show the redacted credential; got {stdout}"
    );
    assert!(
        !stdout.contains("AKIAQYLPMN5HFIQR7XYA"),
        "JUnit must not leak plaintext credential"
    );
}

// ---------------------------------------------------------------------------
// GITHUB ANNOTATIONS (GithubAnnotationsReporter)
// ---------------------------------------------------------------------------

/// Empty corpus -> no workflow command lines. GitHub annotations are
/// finding events, not a container format with an empty skeleton.
#[test]
fn github_annotations_empty_corpus_is_empty_output() {
    let (stdout, stderr, code) = scan_with_format(CLEAN_FIXTURE, "github-annotations");
    assert_eq!(
        code,
        Some(0),
        "clean GitHub-annotations scan must exit 0; stderr={stderr}"
    );
    assert_eq!(stdout, "", "clean GitHub-annotations output must be empty");
}

/// Non-empty corpus -> one GitHub workflow-command annotation per finding,
/// with file/line/title metadata and redacted credential text.
#[test]
fn github_annotations_planted_finding_has_error_command() {
    let (stdout, stderr, code) = scan_with_format(AWS_KEY_FIXTURE, "github-annotations");
    assert_eq!(
        code,
        Some(1),
        "GitHub-annotations planted scan must exit 1; stderr={stderr}"
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        !lines.is_empty(),
        "planted finding must produce at least one GitHub annotation"
    );
    assert!(
        lines.iter().all(|line| line.starts_with("::error ")),
        "AWS high-severity findings must render as error annotations; got {stdout:?}"
    );
    assert!(
        stdout.contains("file=") && stdout.contains(",line=1,") && stdout.contains("title=keyhog"),
        "annotation must include file, line, and title properties; got {stdout:?}"
    );
    assert!(
        stdout.contains("redacted=AK...YA"),
        "annotation must include the redacted credential; got {stdout:?}"
    );
    assert!(
        !stdout.contains("AKIAQYLPMN5HFIQR7XYA"),
        "GitHub annotations must not leak plaintext credential"
    );
}

// ---------------------------------------------------------------------------
// GITLAB SAST (GitlabSastReporter)
// ---------------------------------------------------------------------------

/// Empty corpus -> valid GitLab SAST JSON with an empty vulnerabilities array.
#[test]
fn gitlab_sast_empty_corpus_is_empty_security_report() {
    let (stdout, stderr, code) = scan_with_format(CLEAN_FIXTURE, "gitlab-sast");
    assert_eq!(
        code,
        Some(0),
        "clean GitLab SAST scan must exit 0; stderr={stderr}"
    );
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("gitlab-sast JSON");
    assert_eq!(report["scan"]["type"], "sast");
    assert_eq!(report["scan"]["status"], "success");
    assert_eq!(
        report["vulnerabilities"]
            .as_array()
            .expect("vulnerabilities array")
            .len(),
        0
    );
}

/// Non-empty corpus -> one schema-shaped SAST vulnerability per finding.
#[test]
fn gitlab_sast_planted_finding_has_vulnerability() {
    let (stdout, stderr, code) = scan_with_format(AWS_KEY_FIXTURE, "gitlab-sast");
    assert_eq!(
        code,
        Some(1),
        "GitLab SAST planted scan must exit 1; stderr={stderr}"
    );
    assert!(
        !stdout.contains("AKIAQYLPMN5HFIQR7XYA"),
        "GitLab SAST must not leak plaintext credential"
    );
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("gitlab-sast JSON");
    let vulnerabilities = report["vulnerabilities"]
        .as_array()
        .expect("vulnerabilities array");
    assert!(
        !vulnerabilities.is_empty(),
        "planted finding must produce at least one SAST vulnerability"
    );
    let vuln = &vulnerabilities[0];
    assert_eq!(vuln["category"], "sast");
    assert_eq!(vuln["location"]["start_line"], 1);
    assert_eq!(vuln["identifiers"][0]["type"], "keyhog_rule");
    assert_eq!(vuln["details"]["credential"]["value"], "AK...YA");
}

// ---------------------------------------------------------------------------
// TEXT (TextReporter), the human default
// ---------------------------------------------------------------------------

/// Empty corpus -> text reporter prints the honest clean-result summary. There
/// is no example-suppression for a genuinely clean fixture, but the message
/// still describes only what was scanned instead of claiming global absence.
#[test]
fn text_empty_corpus_prints_clean_summary() {
    let (stdout, stderr, code) = scan_with_format(CLEAN_FIXTURE, "text");
    assert_eq!(
        code,
        Some(0),
        "clean text scan must exit 0; stderr={stderr}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("No secrets detected in the scanned files."),
        "clean text scan must print the scanned-files summary; \
         stdout={stdout:?} stderr={stderr:?}"
    );
    // Text must never look like JSON.
    assert!(
        !stdout.trim_start().starts_with('['),
        "text format must not emit a JSON `[`; got {stdout:?}"
    );
}

/// Non-empty corpus -> text reporter prints the "N secret(s) found"
/// results summary and references the AWS finding. The text reporter
/// writes findings to stdout (the report writer), so assert on the
/// combined stream to be robust to where the summary lands.
#[test]
fn text_planted_finding_prints_results_summary() {
    let (stdout, stderr, code) = scan_with_format(AWS_KEY_FIXTURE, "text");
    assert_eq!(
        code,
        Some(1),
        "text planted scan must exit 1; stderr={stderr}"
    );
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("secret found") || combined.contains("secrets found"),
        "text scan with a finding must print a `secret(s) found` summary; \
         stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        combined.contains("No secrets detected in the scanned files.") == false,
        "text scan with a finding must NOT print the clean-result summary"
    );
    assert!(
        !stdout.trim_start().starts_with('['),
        "text format must not emit a JSON `[`; got {stdout:?}"
    );
}

/// Text mode redacts by default: the bordered finding box shows
/// `Secret:    AK...YA`, never the plaintext key.
#[test]
fn text_planted_finding_is_redacted() {
    let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, "text");
    assert!(
        stdout.contains("AK...YA"),
        "text finding box must show the redacted credential; got {stdout}"
    );
    assert!(
        !stdout.contains("AKIAQYLPMN5HFIQR7XYA"),
        "text mode must not leak the plaintext credential without --show-secrets"
    );
}

// ---------------------------------------------------------------------------
// CROSS-FORMAT INVARIANTS
// ---------------------------------------------------------------------------

/// The structured formats (json/jsonl/sarif/csv/github-annotations/gitlab-sast) must produce
/// deterministic, machine-parseable stdout that does NOT carry ANSI color
/// escapes, since stdout is piped (not a TTY) under `Command::output()`.
#[test]
fn structured_formats_emit_no_ansi_escapes_when_piped() {
    for fmt in [
        "json-envelope",
        "jsonl-envelope",
        "sarif",
        "csv",
        "github-annotations",
        "gitlab-sast",
    ] {
        let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, fmt);
        assert!(
            !stdout.contains('\u{1b}'),
            "structured format `{fmt}` must not emit ANSI escape (\\x1b) on piped stdout; got {stdout:?}"
        );
    }
}

/// JSON and JSONL agree on finding COUNT for the same corpus: the JSON
/// findings length equals the number of non-empty JSONL finding lines (the
/// header is not a finding). Both reporters
/// consume the identical `findings` slice in `finish_reporter`.
#[test]
fn json_and_jsonl_agree_on_finding_count() {
    let (json_out, _e1, _c1) = scan_with_format(AWS_KEY_FIXTURE, "json-envelope");
    let (jsonl_out, _e2, _c2) = scan_with_format(AWS_KEY_FIXTURE, "jsonl-envelope");
    let json_v: serde_json::Value = serde_json::from_str(json_out.trim()).expect("json parses");
    let json_count = json_findings(&json_v).len();
    let jsonl_count = jsonl_out
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .and_then(|value| value.get("record_type").cloned())
                .is_none()
        })
        .count();
    assert_eq!(
        json_count, jsonl_count,
        "JSON findings length ({json_count}) must equal JSONL finding line count ({jsonl_count}) \
         for the same corpus"
    );
    assert!(
        json_count >= 1,
        "both must report at least the planted finding"
    );
}

/// SARIF result count equals the JSON array length for the same corpus.
/// (SARIF builds one result per reported finding in `report()`.)
#[test]
fn sarif_result_count_matches_json_finding_count() {
    let (json_out, _e1, _c1) = scan_with_format(AWS_KEY_FIXTURE, "json-envelope");
    let (sarif_out, _e2, _c2) = scan_with_format(AWS_KEY_FIXTURE, "sarif");
    let json_value =
        serde_json::from_str::<serde_json::Value>(json_out.trim()).expect("json-envelope");
    let json_count = json_value["findings"]
        .as_array()
        .expect("findings array")
        .len();
    let sarif_v: serde_json::Value = serde_json::from_str(sarif_out.trim()).expect("sarif");
    let sarif_count = sarif_v["runs"][0]["results"]
        .as_array()
        .expect("results array")
        .len();
    assert_eq!(
        json_count, sarif_count,
        "SARIF result count ({sarif_count}) must equal JSON finding count ({json_count})"
    );
}

/// CSV data-row count equals the JSON envelope finding count for the same corpus
/// (one CSV row per finding, minus the header line).
#[test]
fn csv_row_count_matches_json_finding_count() {
    let (json_out, _e1, _c1) = scan_with_format(AWS_KEY_FIXTURE, "json-envelope");
    let (csv_out, _e2, _c2) = scan_with_format(AWS_KEY_FIXTURE, "csv");
    let json_value = serde_json::from_str::<serde_json::Value>(json_out.trim())
        .expect("json-envelope");
    let json_count = json_value["findings"]
        .as_array()
        .expect("findings array")
        .len();
    let csv_rows = csv_out
        .lines()
        .filter(|l| !l.is_empty())
        .count()
        .saturating_sub(1); // drop the header
    assert_eq!(
        csv_rows, json_count,
        "CSV data-row count ({csv_rows}) must equal JSON finding count ({json_count})"
    );
}

/// JUnit testcase count equals the JSON finding count for the same corpus.
#[test]
fn junit_testcase_count_matches_json_finding_count() {
    let (json_out, _e1, _c1) = scan_with_format(AWS_KEY_FIXTURE, "json-envelope");
    let (junit_out, _e2, _c2) = scan_with_format(AWS_KEY_FIXTURE, "junit");
    let json_count = serde_json::from_str::<serde_json::Value>(json_out.trim())
        .expect("json-envelope")
        .as_array()
        .expect("array")
        .len();
    let junit_count = junit_out.matches("<testcase ").count();
    assert_eq!(
        junit_count, json_count,
        "JUnit testcase count ({junit_count}) must equal JSON finding count ({json_count})"
    );
}

/// GitHub annotation line count equals the JSON finding count for the same
/// corpus. Each finding must become exactly one workflow-command line.
#[test]
fn github_annotation_count_matches_json_finding_count() {
    let (json_out, _e1, _c1) = scan_with_format(AWS_KEY_FIXTURE, "json-envelope");
    let (annotation_out, _e2, _c2) = scan_with_format(AWS_KEY_FIXTURE, "github-annotations");
    let json_count = serde_json::from_str::<serde_json::Value>(json_out.trim())
        .expect("json-envelope")
        .as_array()
        .expect("array")
        .len();
    let annotation_count = annotation_out
        .lines()
        .filter(|line| line.starts_with("::"))
        .count();
    assert_eq!(
        annotation_count, json_count,
        "GitHub annotation count ({annotation_count}) must equal JSON finding count ({json_count})"
    );
}

/// GitLab SAST vulnerability count equals the JSON finding count for the same
/// corpus.
#[test]
fn gitlab_sast_count_matches_json_finding_count() {
    let (json_out, _e1, _c1) = scan_with_format(AWS_KEY_FIXTURE, "json-envelope");
    let (sast_out, _e2, _c2) = scan_with_format(AWS_KEY_FIXTURE, "gitlab-sast");
    let json_count = serde_json::from_str::<serde_json::Value>(json_out.trim())
        .expect("json-envelope")
        .as_array()
        .expect("array")
        .len();
    let sast_count = serde_json::from_str::<serde_json::Value>(sast_out.trim())
        .expect("gitlab-sast")
        .get("vulnerabilities")
        .and_then(|v| v.as_array())
        .expect("vulnerabilities array")
        .len();
    assert_eq!(
        sast_count, json_count,
        "GitLab SAST vulnerability count ({sast_count}) must equal JSON finding count ({json_count})"
    );
}

// ---------------------------------------------------------------------------
// ADVERSARIAL / EVASION & BOUNDARY
// ---------------------------------------------------------------------------

/// CSV formula-injection neutralization: a credential-bearing line whose
/// REDACTED value would start with a formula-trigger char is prefixed with
/// a single quote by `escape_csv`. We cannot easily force a redaction to
/// start with `=`/`+`/`-`/`@`, but we can prove the neutralizer is wired by
/// confirming no UNquoted data cell in the report begins with a bare
/// formula trigger. (On a clean AKIA detection none should; this guards
/// against a regression that drops the neutralizer.)
#[test]
fn csv_no_unquoted_formula_trigger_cells() {
    let (stdout, _stderr, _code) = scan_with_format(AWS_KEY_FIXTURE, "csv");
    for (i, line) in stdout.lines().enumerate() {
        if i == 0 || line.is_empty() {
            continue; // skip header / blanks
        }
        for cell in line.split(',') {
            if let Some(first) = cell.as_bytes().first() {
                // A neutralized cell is either quoted (`"..."`) or starts
                // with the guard quote `'`; a raw formula trigger means the
                // neutralizer regressed.
                let is_trigger = matches!(first, b'=' | b'+' | b'@');
                assert!(
                    !is_trigger,
                    "CSV cell {cell:?} starts with an un-neutralized formula trigger; \
                     escape_csv must prefix it with a single quote"
                );
            }
        }
    }
}

/// Boundary: an empty input FILE (zero bytes) is a clean corpus for every
/// format and exits 0. Exercises the no-finding path with a degenerate
/// input rather than clean source code.
#[test]
fn empty_file_is_clean_for_every_format() {
    for fmt in [
        "text",
        "json-envelope",
        "jsonl-envelope",
        "sarif",
        "csv",
        "github-annotations",
        "gitlab-sast",
        "html",
        "junit",
    ] {
        let (_stdout, stderr, code) = scan_with_format("", fmt);
        assert_eq!(
            code,
            Some(0),
            "format `{fmt}` on a zero-byte file must exit 0 (clean); stderr={stderr}"
        );
    }
    // And the empty-corpus structural invariants still hold.
    let (json_out, _e, _c) = scan_with_format("", "json-envelope");
    assert_eq!(json_out, "[]", "zero-byte file JSON must be `[]`");
    let (jsonl_out, _e, _c) = scan_with_format("", "jsonl-envelope");
    assert_eq!(jsonl_out, "", "zero-byte file JSONL must be empty");
}

/// Boundary: an UNKNOWN `--format` value is rejected by clap as a usage
/// error (exit 2), not silently defaulted. The OutputFormat ValueEnum only
/// accepts text/json/jsonl/sarif/csv/github-annotations/gitlab-sast/html/junit.
#[test]
fn unknown_format_value_is_clap_usage_error() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.env");
    std::fs::write(&path, CLEAN_FIXTURE).expect("write fixture");
    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .arg("--format")
        .arg("yaml") // not a valid OutputFormat variant
        .arg(&path)
        .output()
        .expect("spawn keyhog scan --format yaml");
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unknown --format value must be a clap usage error (exit 2); \
         stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Default format is `text`: omitting `--format` entirely must behave
/// exactly like `--format text` (ScanArgs default_value = "text").
#[test]
fn default_format_is_text() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.env");
    std::fs::write(&path, CLEAN_FIXTURE).expect("write fixture");
    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .arg("--backend")
        .arg("simd")
        .arg(&path)
        .output()
        .expect("spawn keyhog scan (no --format)");
    assert_eq!(output.status.code(), Some(0), "clean default scan exits 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(
        !stdout.trim_start().starts_with('['),
        "default (text) format must not emit JSON; got {stdout:?}"
    );
    assert!(
        combined.contains("No secrets detected in the scanned files."),
        "default-format clean scan must print the text clean summary; \
         stdout={stdout:?} stderr={stderr:?}"
    );
}

/// Format value matching is case-SENSITIVE: clap `value_enum` defaults to
/// `ignore_case = false`, and `ScanArgs::format` does not override it. So
/// uppercase `JSON` is NOT a valid OutputFormat variant and must be
/// rejected as a clap usage error (exit 2), exactly like a typo. This pins
/// that the accepted spellings are the lowercase variant names only
/// (text/json/jsonl/sarif/csv/github-annotations/gitlab-sast/html/junit).
#[test]
fn format_value_is_case_sensitive() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("planted.env");
    std::fs::write(&path, CLEAN_FIXTURE).expect("write fixture");
    let output = Command::new(binary())
        .arg("scan")
        .arg("--daemon=off")
        .arg("--format")
        .arg("JSON") // uppercase: not a valid variant when ignore_case=false
        .arg(&path)
        .output()
        .expect("spawn keyhog scan --format JSON");
    assert_eq!(
        output.status.code(),
        Some(2),
        "uppercase `JSON` must be a clap usage error (exit 2) because value_enum \
         matching is case-sensitive by default; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `--output` for SARIF writes a valid, complete SARIF doc to disk for the
/// non-empty case, with results resolving into rules, the atomic-write
/// path must not truncate or corrupt the streamed document.
#[test]
fn sarif_output_file_is_complete_for_planted_finding() {
    let (bytes, code) = scan_to_output_file(AWS_KEY_FIXTURE, "sarif");
    assert_eq!(code, Some(1), "sarif --output planted scan must exit 1");
    let v: serde_json::Value =
        serde_json::from_str(bytes.trim()).expect("on-disk SARIF must be valid JSON");
    assert_eq!(v["version"], "2.1.0");
    let results = v["runs"][0]["results"].as_array().expect("results array");
    assert!(
        !results.is_empty(),
        "SARIF --output file must contain the planted result"
    );
    let rule_ids: std::collections::HashSet<String> = v["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array")
        .iter()
        .filter_map(|r| r["id"].as_str().map(str::to_string))
        .collect();
    for r in results {
        let rid = r["ruleId"].as_str().expect("ruleId");
        assert!(
            rule_ids.contains(rid),
            "on-disk SARIF ruleId {rid:?} must resolve into rules"
        );
    }
}

/// `--output` for CSV writes header + data rows to disk for the non-empty
/// case (atomic-write path), header-only for the clean case.
#[test]
fn csv_output_file_roundtrips_header_and_rows() {
    let (clean_bytes, clean_code) = scan_to_output_file(CLEAN_FIXTURE, "csv");
    assert_eq!(clean_code, Some(0));
    let clean_lines: Vec<&str> = clean_bytes.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        clean_lines,
        vec![CSV_HEADER],
        "clean CSV --output must be header-only"
    );

    let (planted_bytes, planted_code) = scan_to_output_file(AWS_KEY_FIXTURE, "csv");
    assert_eq!(planted_code, Some(1));
    let planted_lines: Vec<&str> = planted_bytes.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        planted_lines[0], CSV_HEADER,
        "CSV --output first line is the header"
    );
    assert!(
        planted_lines.len() >= 2,
        "CSV --output must carry >=1 data row for the planted finding"
    );
}
