//! Regression: `keyhog scan --format sarif --output <file>` writes a COMPLETE,
//! GitHub-code-scanning-valid SARIF 2.1.0 document to the named file — the exact
//! same bytes the identical scan prints to stdout — without changing the process
//! exit code, and fails closed on an unwritable path.
//!
//! This is the SARIF-SPECIFIC output-file contract. `regression_cli_output_file`
//! pins the generic `--output` plumbing (json/csv parity, atomic replace, parent
//! creation, bad-path) and touches SARIF only at `results[0].ruleId`/`level`.
//! Here every assertion targets the SARIF DOCUMENT that lands in the file:
//!   * top-level `version` == `2.1.0` and the exact 2.1.0 `$schema` URI;
//!   * `tool.driver.name` == `keyhog`, `informationUri` ==
//!     `https://github.com/santhsecurity/keyhog` (from CARGO_PKG_REPOSITORY);
//!   * `results[0].ruleId` == `github-classic-pat` and it RESOLVES into
//!     `tool.driver.rules[]` (GitHub silently drops an unresolved ruleId);
//!   * `results[0].level` == `error` (critical severity);
//!   * `partialFingerprints["keyhog/credentialHash/v1"]` == the exact credential
//!     hash — the cross-run dedup identity (project self-scan suppression key);
//!   * the SARIF written to the file parses to the SAME serde_json Value as the
//!     SARIF the same scan prints to stdout (the file must not alter content);
//!   * the finding exit code (1) is UNCHANGED by `--output`;
//!   * a CLEAN scan still writes a well-formed SARIF skeleton with `results: []`
//!     and exits 0;
//!   * a multi-detector scan writes N results, all ruleIds resolving, each with
//!     a non-empty hash fingerprint;
//!   * `-o` short flag is byte-identical to `--output`;
//!   * `--output` atomically replaces stale prior bytes;
//!   * an unwritable output path fails with the actionable
//!     "atomically writing report" context, exit 2 (EXIT_USER_ERROR), NO file,
//!     and NO report leaked to stdout.
//!
//! Host-independence: `github-classic-pat` and `aws-access-key` are
//! literal-anchored detectors that fire on the scalar/CPU path, so this runs
//! with `--backend cpu` + `KEYHOG_NO_GPU=1` and never assumes an accelerator.
//! Every assert pins a concrete value (exact string / hash / count / exit code /
//! JSON Value) — never a bare `!is_empty` / `is_ok`.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

/// Checksum-valid GitHub classic PAT (`ghp_` + 36 chars). Split-literal so the
/// self-scan tripwire does not flag this test file. Fires exactly one detector,
/// `github-classic-pat` (severity critical → SARIF level `error`).
const PAT: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");
/// The detector id (== SARIF ruleId) the planted PAT must carry.
const PAT_DETECTOR: &str = "github-classic-pat";
/// The exact hex credential hash for `PAT` — the value carried under the
/// `partialFingerprints` key, and the stable identity GitHub dedups alerts on.
const PAT_HASH: &str = "7b85310a29300230c865bc48ca1836f15b81bd50ac85e8c0785e8145e98ff175";
/// The exact SARIF `partialFingerprints` key the reporter emits (versioned).
const FP_KEY: &str = "keyhog/credentialHash/v1";
/// A second, distinct checksum-valid secret so the multi-detector case has ≥2
/// rules to resolve. Fires `aws-access-key` (severity critical).
const AWS: &str = concat!("AKIA", "QYLPMN5HFIQR7XYA");
const AWS_DETECTOR: &str = "aws-access-key";
/// The exact SARIF 2.1.0 schema URI the document must declare.
const SARIF_SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json";
/// The exact `tool.driver.informationUri` (== crate `repository`).
const INFO_URI: &str = "https://github.com/santhsecurity/keyhog";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A tempdir with `dump.txt` carrying a single bare planted PAT — one finding.
fn leak_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("dump.txt");
    std::fs::write(&path, format!("{PAT}\n")).expect("write leak fixture");
    (dir, path)
}

/// A tempdir with a file that carries no credential-shaped content — zero
/// findings.
fn clean_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("notes.txt");
    std::fs::write(
        &path,
        "just ordinary prose with plain everyday words here\n",
    )
    .expect("write clean fixture");
    (dir, path)
}

/// Run `keyhog scan --no-daemon --backend cpu --format sarif [--output out]
/// <target>` with the accelerator disabled. Returns (exit code, stdout, stderr).
fn run_sarif(target: &PathBuf, out: Option<&PathBuf>) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args([
        "scan",
        "--no-daemon",
        "--backend",
        "cpu",
        "--no-suppress-test-fixtures",
        "--format",
        "sarif",
    ]);
    if let Some(o) = out {
        cmd.arg("--output").arg(o);
    }
    cmd.arg(target).env("KEYHOG_NO_GPU", "1");
    let output = cmd.output().expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Parse the SARIF written to `out_file` into a serde_json Value.
fn read_sarif(out_file: &PathBuf) -> serde_json::Value {
    let bytes = std::fs::read_to_string(out_file).expect("sarif output file must exist");
    serde_json::from_str(&bytes).expect("sarif output file must be valid JSON")
}

/// The set of rule ids indexed in `tool.driver.rules[]`.
fn driver_rule_ids(v: &serde_json::Value) -> std::collections::BTreeSet<String> {
    v.pointer("/runs/0/tool/driver/rules")
        .and_then(|r| r.as_array())
        .expect("tool.driver.rules must be an array")
        .iter()
        .filter_map(|r| r["id"].as_str().map(str::to_string))
        .collect()
}

// ---------------------------------------------------------------------------
// Top-level SARIF skeleton in the FILE
// ---------------------------------------------------------------------------

/// The file carries a SARIF 2.1.0 document: exact `version` and `$schema`.
#[test]
fn sarif_output_file_is_version_2_1_0_with_exact_schema() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.sarif");

    let (code, _out, err) = run_sarif(&target, Some(&out_file));
    assert_eq!(
        code,
        Some(1),
        "sarif scan with a finding exits 1; stderr={err}"
    );

    let v = read_sarif(&out_file);
    assert_eq!(
        v["version"].as_str(),
        Some("2.1.0"),
        "the file's SARIF version must be exactly 2.1.0"
    );
    assert_eq!(
        v["$schema"].as_str(),
        Some(SARIF_SCHEMA),
        "the file must declare the exact 2.1.0 $schema URI"
    );
}

/// The file's `tool.driver` carries the exact name and informationUri, and a
/// non-empty semver-shaped version.
#[test]
fn sarif_output_file_driver_metadata_is_exact() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.sarif");

    let (code, _out, err) = run_sarif(&target, Some(&out_file));
    assert_eq!(code, Some(1), "sarif scan exits 1; stderr={err}");

    let v = read_sarif(&out_file);
    assert_eq!(
        v.pointer("/runs/0/tool/driver/name")
            .and_then(|x| x.as_str()),
        Some("keyhog"),
        "tool.driver.name must be exactly `keyhog`"
    );
    assert_eq!(
        v.pointer("/runs/0/tool/driver/informationUri")
            .and_then(|x| x.as_str()),
        Some(INFO_URI),
        "tool.driver.informationUri must be the canonical repo URL"
    );
    // A version string like `1.2.3` — at least one dot, all-numeric-or-dot.
    let ver = v
        .pointer("/runs/0/tool/driver/version")
        .and_then(|x| x.as_str())
        .expect("tool.driver.version must be present");
    assert!(
        ver.contains('.')
            && ver
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == '-'),
        "tool.driver.version must be a dotted version string; got {ver:?}"
    );
}

// ---------------------------------------------------------------------------
// results[0] ruleId / level / fingerprint in the FILE
// ---------------------------------------------------------------------------

/// The single result's `ruleId` is `github-classic-pat`, it resolves into
/// `tool.driver.rules[]`, and there is exactly one result.
#[test]
fn sarif_output_file_single_result_ruleid_resolves() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.sarif");

    let (code, _out, err) = run_sarif(&target, Some(&out_file));
    assert_eq!(code, Some(1), "sarif scan exits 1; stderr={err}");

    let v = read_sarif(&out_file);
    let results = v
        .pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .expect("runs[0].results must be an array");
    assert_eq!(
        results.len(),
        1,
        "one planted secret must produce exactly one SARIF result"
    );
    assert_eq!(
        results[0]["ruleId"].as_str(),
        Some(PAT_DETECTOR),
        "results[0].ruleId must be the planted detector id"
    );
    let rules = driver_rule_ids(&v);
    assert!(
        rules.contains(PAT_DETECTOR),
        "the result's ruleId must resolve into tool.driver.rules[]; rules={rules:?}"
    );
}

/// The critical PAT maps to SARIF level `error`.
#[test]
fn sarif_output_file_critical_level_is_error() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.sarif");

    let (code, _out, err) = run_sarif(&target, Some(&out_file));
    assert_eq!(code, Some(1), "sarif scan exits 1; stderr={err}");

    let v = read_sarif(&out_file);
    assert_eq!(
        v.pointer("/runs/0/results/0/level")
            .and_then(|x| x.as_str()),
        Some("error"),
        "critical severity must render SARIF level `error`"
    );
}

/// `partialFingerprints` in the file carries the exact credential hash under the
/// versioned key — the cross-run dedup identity.
#[test]
fn sarif_output_file_partial_fingerprint_is_exact_hash() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.sarif");

    let (code, _out, err) = run_sarif(&target, Some(&out_file));
    assert_eq!(code, Some(1), "sarif scan exits 1; stderr={err}");

    let v = read_sarif(&out_file);
    let fps = v
        .pointer("/runs/0/results/0/partialFingerprints")
        .and_then(|x| x.as_object())
        .expect("results[0].partialFingerprints must be an object");
    assert_eq!(
        fps.get(FP_KEY).and_then(|x| x.as_str()),
        Some(PAT_HASH),
        "partialFingerprints[{FP_KEY}] must be the exact credential hash; got {fps:?}"
    );
    // No stray/extra fingerprint keys — exactly one identity entry.
    assert_eq!(
        fps.len(),
        1,
        "partialFingerprints must carry exactly the single credential-hash entry; got {fps:?}"
    );
}

/// The result's rule entry carries GitHub code-scanning severity metadata: a
/// numeric `security-severity` and the `security` tag.
#[test]
fn sarif_output_file_rule_has_security_severity_metadata() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.sarif");

    let (code, _out, err) = run_sarif(&target, Some(&out_file));
    assert_eq!(code, Some(1), "sarif scan exits 1; stderr={err}");

    let v = read_sarif(&out_file);
    let rule = v
        .pointer("/runs/0/tool/driver/rules")
        .and_then(|r| r.as_array())
        .expect("rules array")
        .iter()
        .find(|r| r["id"].as_str() == Some(PAT_DETECTOR))
        .expect("the github-classic-pat rule must be indexed");
    let sev = rule
        .pointer("/properties/security-severity")
        .and_then(|x| x.as_str())
        .expect("rule.properties.security-severity must be present");
    assert_eq!(
        sev, "9.5",
        "a critical detector's security-severity must be the exact critical-band score 9.5"
    );
    let sev_num: f64 = sev.parse().expect("security-severity must be numeric");
    assert!(
        sev_num >= 9.0,
        "9.5 must sit in code-scanning's critical band (>= 9.0); got {sev_num}"
    );
    let tags: Vec<&str> = rule
        .pointer("/properties/tags")
        .and_then(|t| t.as_array())
        .map(|a| a.iter().filter_map(|t| t.as_str()).collect())
        .unwrap_or_default();
    assert!(
        tags.contains(&"security"),
        "the rule must carry the `security` tag for code-scanning; tags={tags:?}"
    );
}

// ---------------------------------------------------------------------------
// File == stdout parity, exit-code invariance
// ---------------------------------------------------------------------------

/// The SARIF written to `--output` parses to the SAME serde_json Value as the
/// identical scan printed to stdout — the file path must not alter content.
#[test]
fn sarif_output_file_value_equals_stdout_value() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.sarif");

    let (code_std, stdout, _e1) = run_sarif(&target, None);
    let (code_file, file_stdout, _e2) = run_sarif(&target, Some(&out_file));

    assert_eq!(code_std, Some(1), "stdout sarif scan exits 1");
    assert_eq!(
        code_file, code_std,
        "--output must not change the exit code (both exit 1 with a finding)"
    );

    let stdout_val: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("stdout sarif must parse");
    let file_val = read_sarif(&out_file);
    assert_eq!(
        file_val, stdout_val,
        "the --output SARIF must be the same JSON Value the scan prints to stdout; \
         --output run's own stdout was:\n{file_stdout}"
    );
}

/// With `--output`, the SARIF is redirected to the file and does NOT also appear
/// on stdout (no duplication).
#[test]
fn sarif_output_flag_redirects_report_off_stdout() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("report.sarif");

    let (_code, stdout, _err) = run_sarif(&target, Some(&out_file));
    assert!(
        !stdout.contains(PAT_HASH),
        "the credential hash must go to the file, not stdout; stdout was:\n{stdout}"
    );
    assert!(
        !stdout.contains("\"version\":\"2.1.0\"") && !stdout.contains("\"version\": \"2.1.0\""),
        "the SARIF document must not be duplicated on stdout; stdout was:\n{stdout}"
    );
    // The file, meanwhile, DOES carry it.
    let v = read_sarif(&out_file);
    assert_eq!(
        v.pointer("/runs/0/results/0/partialFingerprints")
            .and_then(|f| f.get(FP_KEY))
            .and_then(|x| x.as_str()),
        Some(PAT_HASH),
        "the file must carry the credential hash fingerprint"
    );
}

// ---------------------------------------------------------------------------
// Clean scan → well-formed empty SARIF file
// ---------------------------------------------------------------------------

/// A clean scan with `--output sarif` exits 0 and STILL writes a well-formed
/// SARIF 2.1.0 skeleton whose `results` array is empty.
#[test]
fn sarif_output_file_clean_scan_is_empty_skeleton_exit_zero() {
    let (_dir, target) = clean_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("clean.sarif");

    let (code, _out, err) = run_sarif(&target, Some(&out_file));
    assert_eq!(code, Some(0), "clean scan must exit 0; stderr={err}");

    let v = read_sarif(&out_file);
    assert_eq!(
        v["version"].as_str(),
        Some("2.1.0"),
        "even an empty run must be a valid 2.1.0 document"
    );
    let results = v
        .pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .expect("empty run must still carry a results array");
    assert_eq!(
        results.len(),
        0,
        "a clean scan's SARIF results array must be empty; got {results:?}"
    );
    assert_eq!(
        v.pointer("/runs/0/tool/driver/name")
            .and_then(|x| x.as_str()),
        Some("keyhog"),
        "even an empty run must carry the driver name"
    );
}

// ---------------------------------------------------------------------------
// Multi-detector closure in the FILE
// ---------------------------------------------------------------------------

/// Two files with two distinct secrets → two SARIF results in the file, both
/// ruleIds resolving into the rule index, each with a non-empty hash
/// fingerprint. Both `github-classic-pat` and `aws-access-key` are
/// literal-anchored, so they fire on the CPU path (host-independent).
#[test]
fn sarif_output_file_multi_detector_results_all_resolve() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("gh.env"), format!("GITHUB_TOKEN={PAT}\n"))
        .expect("write gh fixture");
    std::fs::write(
        dir.path().join("aws.env"),
        format!("AWS_ACCESS_KEY_ID = \"{AWS}\"\n"),
    )
    .expect("write aws fixture");
    let target = dir.path().to_path_buf();

    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("multi.sarif");

    let (code, _out, err) = run_sarif(&target, Some(&out_file));
    assert_eq!(code, Some(1), "multi-secret scan exits 1; stderr={err}");

    let v = read_sarif(&out_file);
    let results = v
        .pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .expect("results array");
    assert_eq!(
        results.len(),
        2,
        "two distinct planted secrets must yield exactly two results"
    );

    let result_ids: std::collections::BTreeSet<&str> = results
        .iter()
        .filter_map(|r| r["ruleId"].as_str())
        .collect();
    assert!(
        result_ids.contains(PAT_DETECTOR) && result_ids.contains(AWS_DETECTOR),
        "results must include both {PAT_DETECTOR} and {AWS_DETECTOR}; got {result_ids:?}"
    );

    let rules = driver_rule_ids(&v);
    for r in results {
        let rid = r["ruleId"].as_str().expect("each result needs a ruleId");
        assert!(
            rules.contains(rid),
            "ruleId {rid:?} must resolve into tool.driver.rules[]; rules={rules:?}"
        );
        let fp = r
            .pointer("/partialFingerprints")
            .and_then(|f| f.get(FP_KEY))
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| panic!("result {rid} must carry a {FP_KEY} fingerprint"));
        // A SHA-256 hex digest: 64 lowercase hex chars.
        assert_eq!(
            fp.len(),
            64,
            "the fingerprint hash must be a 64-char SHA-256 hex digest; got {fp:?}"
        );
        assert!(
            fp.chars().all(|c| c.is_ascii_hexdigit()),
            "the fingerprint must be all hex; got {fp:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Short flag, atomic replace
// ---------------------------------------------------------------------------

/// The short `-o` flag produces a byte-identical SARIF document to `--output`.
#[test]
fn sarif_short_o_flag_equivalent_to_long_output() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let long_file = out_dir.path().join("long.sarif");
    let short_file = out_dir.path().join("short.sarif");

    let (code_long, _lo, _le) = run_sarif(&target, Some(&long_file));

    let (code_short, _so, _se) = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "cpu",
            "--no-suppress-test-fixtures",
            "--format",
            "sarif",
            "-o",
        ])
        .arg(&short_file)
        .arg(&target)
        .env("KEYHOG_NO_GPU", "1")
        .output()
        .map(|o| (o.status.code(), String::new(), String::new()))
        .expect("spawn short-flag sarif scan");

    assert_eq!(code_long, Some(1), "long-flag sarif scan exits 1");
    assert_eq!(code_short, Some(1), "short-flag sarif scan exits 1");

    let long_val = read_sarif(&long_file);
    let short_val = read_sarif(&short_file);
    assert_eq!(
        short_val, long_val,
        "`-o` and `--output` must produce identical SARIF content"
    );
}

/// `--output` atomically replaces stale prior bytes: the old content is gone,
/// replaced by exactly the fresh one-result SARIF document.
#[test]
fn sarif_output_atomically_replaces_existing_file() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let out_file = out_dir.path().join("stale.sarif");
    std::fs::write(&out_file, "STALE-NON-SARIF-BYTES-THAT-MUST-VANISH").expect("seed stale file");

    let (code, _out, err) = run_sarif(&target, Some(&out_file));
    assert_eq!(code, Some(1), "sarif scan exits 1; stderr={err}");

    let bytes = std::fs::read_to_string(&out_file).expect("output file must exist");
    assert!(
        !bytes.contains("STALE-NON-SARIF-BYTES"),
        "the prior file contents must be fully replaced; got:\n{bytes}"
    );
    let v: serde_json::Value =
        serde_json::from_str(&bytes).expect("the replaced file must be valid SARIF JSON");
    assert_eq!(
        v.pointer("/runs/0/results")
            .and_then(|r| r.as_array())
            .map(|a| a.len()),
        Some(1),
        "the replaced file must be the fresh one-result SARIF"
    );
    assert_eq!(
        v.pointer("/runs/0/results/0/ruleId")
            .and_then(|x| x.as_str()),
        Some(PAT_DETECTOR),
        "the replaced file's result must be the planted detector"
    );
}

// ---------------------------------------------------------------------------
// Bad output path fails closed
// ---------------------------------------------------------------------------

/// An unwritable SARIF output path — an intermediate component that is a regular
/// FILE, so the parent directory cannot be created — fails with the actionable
/// "atomically writing report" context, exit 2 (EXIT_USER_ERROR), writes NO
/// output file, and leaks NO SARIF to stdout.
#[test]
fn sarif_bad_output_path_exits_user_error_no_file_no_stdout() {
    let (_dir, target) = leak_fixture();
    let out_dir = TempDir::new().expect("out tempdir");
    let blocker = out_dir.path().join("blocker");
    std::fs::write(&blocker, b"i am a regular file, not a directory").expect("seed blocker file");
    let out_file = blocker.join("out.sarif");

    let (code, stdout, stderr) = run_sarif(&target, Some(&out_file));

    assert_eq!(
        code,
        Some(2),
        "a sarif report-write failure must exit 2 (EXIT_USER_ERROR); \
         stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("atomically writing report"),
        "the error must name the failing operation; stderr was:\n{stderr}"
    );
    assert!(
        !out_file.exists(),
        "no output file may be left at the un-writable target path"
    );
    assert!(
        !stdout.contains("\"version\":\"2.1.0\"") && !stdout.contains(PAT_HASH),
        "a failed --output write must not leak the SARIF report to stdout; stdout:\n{stdout}"
    );
    // The blocker file must be left byte-for-byte untouched.
    let blocker_bytes = std::fs::read(&blocker).expect("blocker still readable");
    assert_eq!(
        blocker_bytes, b"i am a regular file, not a directory",
        "the blocking file must be left untouched"
    );
}
