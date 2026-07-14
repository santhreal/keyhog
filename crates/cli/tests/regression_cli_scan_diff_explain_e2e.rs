//! Regression e2e, the operator-facing `scan` / `diff` / `explain` surfaces,
//! driven over the SHIPPED `keyhog` binary and pinned to EXACT values.
//!
//! Every assertion here pins a concrete, load-bearing value, an exact exit
//! code, detector id, service string, severity token, redacted-credential
//! byte sequence, SARIF `ruleId` / `level` / rule name, JSON `location.line`
//! integer, credential-hash length, diff category counts, or explain body
//! text. No assertion uses `is_empty()` / `is_ok()` / `len() > 0` as its only
//! check (Law 6).
//!
//! Distinct from `lane5_scan_flag_and_exit_matrix.rs` (which pins the
//! backend×format grid and exit-code matrix): this file pins the *finding
//! payload* (`location.file_path`, `location.line`, dedup `additional_locations`),
//! the *SARIF rule metadata* (driver name/version, rule `name`, result `level`),
//! the *explain body* (name/service/severity lines, rotation URL, remediation
//! steps, `hot-*` fast-path label resolution), and the *diff category counts*
//! in both `--json` and text forms.
//!
//! All scans run `--daemon=off --backend cpu` (the always-available,
//! feature-independent engine) and clear `KEYHOG_BACKEND` so the CLI flag is
//! the only routing input.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A GitHub classic PAT with a VALID CRC32 tail (the token used across the
/// scanner boundary/parity suites). It fires `github-classic-pat` at
/// confidence 0.9 with a passing checksum, so it survives the confidence floor
/// on every backend. Split-literal so this test file is not itself a planted
/// secret for a self-scan.
const PLANTED: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");
const DETECTOR_ID: &str = "github-classic-pat";
const DETECTOR_NAME: &str = "GitHub Classic PAT";
const SERVICE: &str = "github";
const SEVERITY: &str = "critical";
/// Default-redaction form (`first4…last4`) the masked report must emit.
const REDACTED: &str = "ghp_...DSiF";
/// The curated github rotation-guide URL `explain` prints (see
/// `subcommands/explain.rs::rotation_guide`).
const GITHUB_ROTATION_URL: &str = "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens";
/// The curated aws rotation-guide URL.
const AWS_ROTATION_URL: &str = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey";

/// Run `keyhog scan --daemon=off --backend cpu <extra…> <path>` hermetically and
/// return (exit-code, stdout, stderr).
fn scan(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--backend", "cpu"]);
    cmd.args(extra);
    cmd.arg(path);
    cmd.env_remove("KEYHOG_BACKEND");
    cmd.env("NO_COLOR", "1");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Run `keyhog explain <id> [extra…]` and return (exit-code, stdout, stderr).
fn explain(args: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.arg("explain");
    cmd.args(args);
    cmd.env("NO_COLOR", "1");
    let out = cmd.output().expect("spawn keyhog explain");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Parse a `--format json` array report to a serde value, panicking with the
/// raw stdout on failure so a serializer regression is legible.
fn json_report(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout)
        .unwrap_or_else(|e| panic!("stdout is not a JSON report ({e}):\n{stdout}"))
}

/// Every finding in a JSON array report whose `detector_id` equals `id`.
/// Used instead of `report[0]` because a broad-net detector could also fire on
/// the same token; the `github-classic-pat` contract must hold regardless.
fn findings_for<'a>(report: &'a serde_json::Value, id: &str) -> Vec<&'a serde_json::Value> {
    report
        .as_array()
        .expect("report is a JSON array")
        .iter()
        .filter(|f| f["detector_id"].as_str() == Some(id))
        .collect()
}

/// The single `github-classic-pat` finding, panicking if it is absent or
/// duplicated (dedup across the scan must collapse it to exactly one).
fn sole_pat_finding(report: &serde_json::Value) -> &serde_json::Value {
    let hits = findings_for(report, DETECTOR_ID);
    assert_eq!(
        hits.len(),
        1,
        "exactly one {DETECTOR_ID} finding expected (cross-scan dedup); got {}",
        report
    );
    hits[0]
}

/// A temp directory holding a single file with the planted PAT.
fn planted_dir(filename: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(filename);
    std::fs::write(&path, format!("GITHUB_TOKEN={PLANTED}\n")).expect("write planted fixture");
    (dir, path)
}

// ---------------------------------------------------------------------------
// scan, clean tree
// ---------------------------------------------------------------------------

/// A directory of several credential-free files exits 0 and the JSON report is
/// the empty array `[]` (exactly zero findings, not merely "no error").
#[test]
fn clean_directory_exits_zero_with_empty_json_array() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("a.rs"), "fn main() { let x = 1; }\n").expect("write a");
    std::fs::write(
        dir.path().join("b.txt"),
        "just some prose, no secrets here\n",
    )
    .expect("write b");
    std::fs::write(dir.path().join("c.md"), "# readme\n\nnothing to see\n").expect("write c");

    let (code, stdout, stderr) = scan(dir.path(), &["--format", "json"]);
    assert_eq!(
        code,
        Some(0),
        "clean directory must exit 0; stderr={stderr}"
    );
    let v = json_report(&stdout);
    assert_eq!(
        v.as_array().expect("report is a JSON array").len(),
        0,
        "clean directory must produce exactly zero findings; got {stdout}"
    );
}

// ---------------------------------------------------------------------------
// scan, planted finding payload (JSON)
// ---------------------------------------------------------------------------

/// The planted PAT fires `github-classic-pat` and the JSON finding carries the
/// exact detector id, human name, service, and severity token.
#[test]
fn planted_json_has_exact_detector_service_and_severity() {
    let (_dir, path) = planted_dir("leak.env");
    let (code, stdout, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(1), "planted secret must exit 1; stderr={stderr}");

    let v = json_report(&stdout);
    let f = sole_pat_finding(&v);
    assert_eq!(
        f["detector_id"].as_str(),
        Some(DETECTOR_ID),
        "detector_id must be {DETECTOR_ID}; got {stdout}"
    );
    assert_eq!(
        f["detector_name"].as_str(),
        Some(DETECTOR_NAME),
        "detector_name must be {DETECTOR_NAME}; got {stdout}"
    );
    assert_eq!(
        f["service"].as_str(),
        Some(SERVICE),
        "service must be {SERVICE}; got {stdout}"
    );
    assert_eq!(
        f["severity"].as_str(),
        Some(SEVERITY),
        "severity must serialize kebab-case as {SEVERITY}; got {stdout}"
    );
}

/// The JSON finding's `location` block names the exact file the secret was
/// planted in and reports it on line 1 (the token is on the first line).
#[test]
fn planted_json_location_names_file_and_reports_line_one() {
    let (_dir, path) = planted_dir("leak.env");
    let (code, stdout, _stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(1));

    let v = json_report(&stdout);
    let loc = &sole_pat_finding(&v)["location"];

    let file_path = loc["file_path"]
        .as_str()
        .unwrap_or_else(|| panic!("location.file_path must be a string; got {stdout}"));
    assert!(
        file_path.ends_with("leak.env"),
        "location.file_path must name the planted file `leak.env`; got {file_path:?}"
    );
    assert_eq!(
        loc["line"].as_u64(),
        Some(1),
        "the token is on line 1, so location.line must be exactly 1; got {stdout}"
    );
    assert_eq!(
        loc["source"].as_str(),
        Some("filesystem"),
        "a filesystem scan must label the source `filesystem`; got {stdout}"
    );
}

/// The default report redacts to the exact `ghp_...DSiF` byte sequence, never
/// leaks the full token, and the `credential_hash` is a 64-char lowercase-hex
/// SHA-256 digest.
#[test]
fn planted_json_redacts_to_exact_bytes_and_hash_is_64_hex() {
    let (_dir, path) = planted_dir("leak.env");
    let (code, stdout, _stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(1));

    let v = json_report(&stdout);
    let f = sole_pat_finding(&v);
    assert_eq!(
        f["credential_redacted"].as_str(),
        Some(REDACTED),
        "default report must redact to exactly {REDACTED}; got {stdout}"
    );
    assert!(
        !stdout.contains(PLANTED),
        "default report must NOT leak the full token bytes; got {stdout}"
    );

    let hash = f["credential_hash"]
        .as_str()
        .unwrap_or_else(|| panic!("credential_hash must be a hex string; got {stdout}"));
    assert_eq!(
        hash.len(),
        64,
        "credential_hash must be a 64-char SHA-256 hex; got {hash:?}"
    );
    assert!(
        hash.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "credential_hash must be lowercase hex; got {hash:?}"
    );
}

/// Two files holding the SAME token dedup to ONE finding whose primary
/// `location` plus its single `additional_locations` entry cover BOTH files
/// (the credential identity is `(detector, credential)`, path is metadata).
#[test]
fn duplicate_token_across_two_files_dedups_to_one_finding_with_both_paths() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("dup_a.env"), format!("A={PLANTED}\n")).expect("write a");
    std::fs::write(dir.path().join("dup_b.env"), format!("B={PLANTED}\n")).expect("write b");

    let (code, stdout, stderr) = scan(dir.path(), &["--format", "json"]);
    assert_eq!(code, Some(1), "planted dir must exit 1; stderr={stderr}");

    let v = json_report(&stdout);
    let f = sole_pat_finding(&v);
    let additional = f["additional_locations"]
        .as_array()
        .expect("additional_locations array");
    assert_eq!(
        additional.len(),
        1,
        "the duplicate must be recorded as exactly one additional location; got {stdout}"
    );

    // The primary + additional locations together must name both files.
    let mut names: BTreeSet<String> = BTreeSet::new();
    let primary = f["location"]["file_path"].as_str().expect("primary path");
    names.insert(
        Path::new(primary)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned(),
    );
    for loc in additional {
        let p = loc["file_path"].as_str().expect("additional path");
        names.insert(
            Path::new(p)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
        );
    }
    let expected: BTreeSet<String> = ["dup_a.env".to_string(), "dup_b.env".to_string()]
        .into_iter()
        .collect();
    assert_eq!(
        names, expected,
        "the finding must cover both dup_a.env and dup_b.env across its locations"
    );
}

// ---------------------------------------------------------------------------
// scan: SARIF rule metadata
// ---------------------------------------------------------------------------

/// The SARIF report's single result carries `ruleId == github-classic-pat` and
/// a `level == error` (critical severity maps to the SARIF error level).
#[test]
fn sarif_result_has_exact_ruleid_and_error_level() {
    let (_dir, path) = planted_dir("leak.env");
    let (code, stdout, stderr) = scan(&path, &["--format", "sarif"]);
    assert_eq!(code, Some(1), "sarif scan must exit 1; stderr={stderr}");

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("sarif is valid JSON");
    assert_eq!(v["version"], "2.1.0", "SARIF version must be 2.1.0");

    let results = v["runs"][0]["results"].as_array().expect("runs[0].results");
    let result = results
        .iter()
        .find(|r| r["ruleId"].as_str() == Some(DETECTOR_ID))
        .unwrap_or_else(|| panic!("no SARIF result with ruleId {DETECTOR_ID}; got {stdout}"));
    assert_eq!(
        result["level"].as_str(),
        Some("error"),
        "critical severity must map to SARIF level `error`; got {stdout}"
    );
}

/// The SARIF `tool.driver` identifies keyhog with the crate version, and the
/// emitted rule for the planted finding carries the exact human `name`.
#[test]
fn sarif_driver_is_keyhog_and_rule_has_exact_name() {
    let (_dir, path) = planted_dir("leak.env");
    let (code, stdout, _stderr) = scan(&path, &["--format", "sarif"]);
    assert_eq!(code, Some(1));

    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("sarif is valid JSON");
    let driver = &v["runs"][0]["tool"]["driver"];
    assert_eq!(
        driver["name"].as_str(),
        Some("keyhog"),
        "SARIF driver name must be `keyhog`; got {stdout}"
    );
    assert_eq!(
        driver["version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "SARIF driver version must match the crate version"
    );

    let rules = driver["rules"].as_array().expect("driver.rules array");
    let rule = rules
        .iter()
        .find(|r| r["id"].as_str() == Some(DETECTOR_ID))
        .unwrap_or_else(|| panic!("no SARIF rule with id {DETECTOR_ID}; got {stdout}"));
    assert_eq!(
        rule["name"].as_str(),
        Some(DETECTOR_NAME),
        "SARIF rule name must be {DETECTOR_NAME}; got {stdout}"
    );
}

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------

/// `explain github-classic-pat` prints the detector id header, exact name,
/// service, and the `Critical` severity label.
#[test]
fn explain_prints_exact_name_service_and_severity() {
    let (code, stdout, stderr) = explain(&[DETECTOR_ID]);
    assert_eq!(code, Some(0), "explain must exit 0; stderr={stderr}");

    assert!(
        stdout.contains(DETECTOR_ID),
        "explain must print the detector id header; got {stdout}"
    );
    assert!(
        stdout.contains("Name:") && stdout.contains(DETECTOR_NAME),
        "explain must print the Name line with value {DETECTOR_NAME}; got {stdout}"
    );
    assert!(
        stdout.contains("Service:") && stdout.contains("Rotation guide for github:"),
        "explain must print the Service line and github rotation block; got {stdout}"
    );
    assert!(
        stdout.contains("Severity:") && stdout.contains("Critical"),
        "explain must print the Severity line with value Critical; got {stdout}"
    );
}

/// `explain github-classic-pat` prints the curated github rotation-guide URL
/// and the four numbered canonical-remediation steps.
#[test]
fn explain_prints_github_rotation_url_and_remediation_steps() {
    let (code, stdout, _stderr) = explain(&[DETECTOR_ID]);
    assert_eq!(code, Some(0));

    assert!(
        stdout.contains("Rotation guide for github:"),
        "explain must open a github rotation block; got {stdout}"
    );
    assert!(
        stdout.contains(GITHUB_ROTATION_URL),
        "explain must print the exact github rotation URL; got {stdout}"
    );
    assert!(
        stdout.contains("1. Treat the credential as compromised; assume it has been read."),
        "explain must print remediation step 1; got {stdout}"
    );
    assert!(
        stdout.contains("2. Rotate it at the issuer (see rotation-guide URL above)."),
        "explain must print remediation step 2; got {stdout}"
    );
}

/// `explain aws-access-key` resolves a DIFFERENT service and prints the aws
/// rotation URL (proves the rotation-guide map is keyed per-service, not a
/// constant).
#[test]
fn explain_aws_access_key_prints_aws_rotation_url() {
    let (code, stdout, stderr) = explain(&["aws-access-key"]);
    assert_eq!(
        code,
        Some(0),
        "explain aws-access-key must exit 0; stderr={stderr}"
    );
    assert!(
        stdout.contains("Rotation guide for aws:"),
        "explain aws-access-key must open an aws rotation block; got {stdout}"
    );
    assert!(
        stdout.contains(AWS_ROTATION_URL),
        "explain aws-access-key must print the exact aws rotation URL; got {stdout}"
    );
    assert!(
        !stdout.contains(GITHUB_ROTATION_URL),
        "the aws explanation must NOT leak the github rotation URL; got {stdout}"
    );
}

/// `explain <unknown-id>` is a user error: exit 2, and stderr names the id the
/// operator typed so they can see the typo.
#[test]
fn explain_unknown_detector_exits_two_and_names_the_id() {
    let (code, _stdout, stderr) = explain(&["totally-made-up-detector-zzz"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown detector id is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("totally-made-up-detector-zzz"),
        "the error must echo the id the operator typed; got {stderr}"
    );
}

/// A historical fast-path id is not executable. The error names the exact
/// canonical command so operators can migrate old reports without a shim.
#[test]
fn explain_hot_fast_path_label_fails_with_canonical_command() {
    let (code, _stdout, stderr) = explain(&["hot-github_pat"]);
    assert_eq!(
        code,
        Some(2),
        "a retired detector id is a user error; stderr={stderr}"
    );
    assert!(
        stderr.contains(&format!("keyhog explain {DETECTOR_ID}")),
        "the error must give the exact canonical command; got {stderr}"
    );
}

// ---------------------------------------------------------------------------
// diff
// ---------------------------------------------------------------------------

fn baseline_json(entries: &str) -> String {
    format!(r#"{{"version": 1, "created": "test", "entries": [{entries}]}}"#)
}

fn entry_json(detector_id: &str, credential_hash: &str, file_path: &str, line: usize) -> String {
    format!(
        r#"{{"detector_id": "{detector_id}", "credential_hash": "{credential_hash}", "file_path": "{file_path}", "line": {line}, "status": "acknowledged"}}"#
    )
}

/// A finding present in the BEFORE baseline but absent from AFTER is RESOLVED,
/// not NEW: `diff --json` reports resolved=1 / new=0 and exits 0 (no new leak).
#[test]
fn diff_resolved_only_exits_zero_with_exact_json_counts() {
    let dir = TempDir::new().expect("tempdir");
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    std::fs::write(
        &before,
        baseline_json(&entry_json(DETECTOR_ID, "hashaaa", "/a.env", 1)),
    )
    .expect("write before");
    std::fs::write(&after, baseline_json("")).expect("write after");

    let out = Command::new(binary())
        .arg("diff")
        .arg("--json")
        .arg(&before)
        .arg(&after)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn keyhog diff --json");
    assert_eq!(
        out.status.code(),
        Some(0),
        "a diff with only RESOLVED entries has no new leak → exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).expect("diff --json output");
    assert_eq!(
        v["new"].as_array().expect("new array").len(),
        0,
        "no NEW entries; got {v}"
    );
    assert_eq!(
        v["resolved"].as_array().expect("resolved array").len(),
        1,
        "exactly one RESOLVED entry; got {v}"
    );
    assert_eq!(
        v["summary"]["resolved_count"].as_u64(),
        Some(1),
        "summary.resolved_count must be 1; got {v}"
    );
    assert_eq!(
        v["summary"]["new_count"].as_u64(),
        Some(0),
        "summary.new_count must be 0; got {v}"
    );
}

/// BEFORE {A,B} vs AFTER {A,C}: A is UNCHANGED, B is RESOLVED, C is NEW. The
/// text summary must read exactly `FAIL 1` (new), `PASS 1` (resolved),
/// `= 1` (unchanged), and the presence of a NEW entry exits 1.
#[test]
fn diff_mixed_new_resolved_unchanged_reports_exact_summary_and_exits_one() {
    let dir = TempDir::new().expect("tempdir");
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    // A = (aws-access-key, hashA) is in both; B = (slack-bot-token, hashB) only
    // in before; C = (github-classic-pat, hashC) only in after.
    std::fs::write(
        &before,
        baseline_json(&format!(
            "{},{}",
            entry_json("aws-access-key", "hashA", "/a.env", 1),
            entry_json("slack-bot-token", "hashB", "/b.env", 2),
        )),
    )
    .expect("write before");
    std::fs::write(
        &after,
        baseline_json(&format!(
            "{},{}",
            entry_json("aws-access-key", "hashA", "/a.env", 1),
            entry_json(DETECTOR_ID, "hashC", "/c.env", 3),
        )),
    )
    .expect("write after");

    let out = Command::new(binary())
        .arg("diff")
        .arg(&before)
        .arg(&after)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn keyhog diff");
    assert_eq!(
        out.status.code(),
        Some(1),
        "a NEW entry means a new leak → exit 1; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("FAIL 1"),
        "summary must count 1 new as `FAIL 1`; got {stdout}"
    );
    assert!(
        stdout.contains("PASS 1"),
        "summary must count 1 resolved as `PASS 1`; got {stdout}"
    );
    assert!(
        stdout.contains("= 1"),
        "summary must count 1 unchanged as `= 1`; got {stdout}"
    );
}

/// `diff <missing-before> <after>` is a user error: exit 2 and stderr names the
/// missing file so the operator knows which path was wrong.
#[test]
fn diff_missing_before_file_exits_two_and_names_the_file() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("nope-before.json");
    let after = dir.path().join("after.json");
    std::fs::write(&after, baseline_json("")).expect("write after");

    let out = Command::new(binary())
        .arg("diff")
        .arg(&missing)
        .arg(&after)
        .output()
        .expect("spawn keyhog diff <missing>");
    assert_eq!(
        out.status.code(),
        Some(2),
        "a missing before-baseline is a user error → exit 2; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("nope-before.json"),
        "the error must name the missing file; got {stderr}"
    );
}
