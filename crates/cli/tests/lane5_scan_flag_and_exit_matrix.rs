//! LANE 5 (test-cli-e2e), the `keyhog scan` flag matrix and exit-code matrix,
//! driven over the SHIPPED binary with a planted, checksum-valid secret.
//!
//! The contracts pinned here, all end-to-end through the real executable:
//!
//!   * EXIT-CODE MATRIX, clean tree → 0, unverified findings → 1, bad
//!     flag/value/path → 2 (the documented `args.rs` exit contract). Each is a
//!     distinct, separately-asserted case so a regression that collapses two
//!     classes (e.g. a parse error that exits 1 instead of 2) is caught.
//!
//!   * BACKEND × FORMAT GRID, the SAME planted secret must surface under the
//!     explicit `--backend {simd,cpu,gpu}` CLI flag AND under every
//!     `--format {text,json,jsonl,sarif,csv,html,junit}`, with the JSON/JSONL
//!     paths carrying the SAME credential hash. This is a Cartesian product
//!     re-run for structural parse + count,
//!     so a serializer or backend-routing bug that drops the finding on ONE
//!     cell is a recall hole the operator hits by switching a flag.
//!
//!   * MASKING: `--show-secrets` emits the full token; the default redacts to
//!     `ghp_…DSiF`. Asserted on the exact bytes, not a shape.
//!
//!   * `-o` / `--output`: writes the report to a file (atomic-rename path) and
//!     the file parses as the requested format; stdout stays empty.
//!
//!   * BOUNDARIES: `--min-confidence` at 0.0 / 1.0 (valid) and out-of-range
//!     (rejected exit 2); `--severity` filtering; `--no-config` hermetic run.
//!
//! Every assert pins an EXACT exit code, an EXACT detector id / credential
//! hash, an EXACT count, or EXACT bytes, never `!is_empty` (Law 6). All scans
//! pass `--daemon=off` (no background-process nondeterminism), pin `--backend simd`
//! for non-routing assertions, and clear the legacy `KEYHOG_BACKEND` env so the
//! CLI flag is the only routing input.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

#[path = "support/jsonl.rs"]
mod jsonl_support;

use jsonl_support::parse_jsonl_objects;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A planted GitHub classic PAT with a VALID CRC32 tail (the token used across
/// the scanner boundary/parity suites). It fires `github-classic-pat` on its
/// own bytes at confidence 0.9 with a passing checksum, so it survives the
/// confidence floor on every backend and format. Split-literal so this test
/// file is not itself a planted-secret tripwire for a self-scan.
const PLANTED: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");
/// The detector this token must fire, and its stable severity.
const DETECTOR_ID: &str = "github-classic-pat";
const SEVERITY: &str = "critical";
/// The default-redaction form (`first4…last4`) the masked report must emit.
const REDACTED: &str = "ghp_...DSiF";

/// Explicit operator-selectable backends. `auto` is covered by autoroute
/// calibration tests because it
/// correctly fails closed on hosts without persisted calibration evidence.
const BACKENDS: &[&str] = &["simd", "cpu", "gpu"];
/// Every output format the `--format` value-enum accepts.
const FORMATS: &[&str] = &["text", "json", "jsonl", "sarif", "csv", "html", "junit"];

fn planted_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("leak.env");
    std::fs::write(&path, format!("GITHUB_TOKEN={PLANTED}\n")).expect("write fixture");
    (dir, path)
}

fn clean_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("clean.rs");
    std::fs::write(&path, "fn main() { println!(\"no secrets here\"); }\n").expect("write fixture");
    (dir, path)
}

/// Run `keyhog scan --daemon=off <extra…> <path>` with a hermetic env and return
/// (exit-code, stdout, stderr).
fn scan(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off"]);
    if !extra.contains(&"--backend") {
        cmd.args(["--backend", "simd"]);
    }
    cmd.args(extra);
    cmd.arg(path);
    cmd.env_remove("KEYHOG_BACKEND");
    let out = cmd.output().expect("spawn keyhog scan");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// The set of detector ids present in a `--format json` array report.
fn json_detector_ids(stdout: &str) -> BTreeSet<String> {
    let v: serde_json::Value =
        serde_json::from_str(stdout).unwrap_or_else(|e| panic!("stdout not JSON ({e}):\n{stdout}"));
    v.as_array()
        .expect("json report is an array")
        .iter()
        .filter_map(|f| f.get("detector_id").and_then(|d| d.as_str()))
        .map(String::from)
        .collect()
}

/// The set of credential hashes in a `--format json` array report.
fn json_hashes(stdout: &str) -> BTreeSet<String> {
    let v: serde_json::Value =
        serde_json::from_str(stdout).unwrap_or_else(|e| panic!("stdout not JSON ({e}):\n{stdout}"));
    v.as_array()
        .expect("json report is an array")
        .iter()
        .filter_map(|f| f.get("credential_hash").and_then(|h| h.as_str()))
        .map(String::from)
        .collect()
}

// ----------------------------------------------------------------------------
// EXIT-CODE MATRIX
// ----------------------------------------------------------------------------

#[test]
fn clean_tree_exits_zero_with_empty_json_array() {
    let (_dir, path) = clean_fixture();
    let (code, stdout, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(code, Some(0), "clean file must exit 0; stderr={stderr}");
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    assert_eq!(
        v.as_array().expect("array").len(),
        0,
        "clean file must produce zero findings; got {stdout}"
    );
}

#[test]
fn planted_secret_exits_one_with_exactly_the_github_pat() {
    let (_dir, path) = planted_fixture();
    let (code, stdout, stderr) = scan(&path, &["--format", "json"]);
    assert_eq!(
        code,
        Some(1),
        "unverified planted finding must exit 1; stderr={stderr}"
    );
    let ids = json_detector_ids(&stdout);
    assert!(
        ids.contains(DETECTOR_ID),
        "planted ghp_ token must fire {DETECTOR_ID}; got ids={ids:?}"
    );
}

#[test]
fn missing_path_exits_two() {
    let missing = PathBuf::from("/keyhog-lane5-no-such-path-9d3f");
    let (code, _stdout, stderr) = scan(&missing, &["--format", "json"]);
    assert_eq!(
        code,
        Some(2),
        "a path the user named that does not exist is a user error → exit 2; stderr={stderr}"
    );
}

#[test]
fn invalid_backend_value_exits_two() {
    let (_dir, path) = planted_fixture();
    let (code, _stdout, stderr) = scan(&path, &["--backend", "quantum"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown --backend value is a user error → exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("quantum") || stderr.to_lowercase().contains("invalid"),
        "stderr must reject the bad backend value; got {stderr}"
    );
}

#[test]
fn invalid_format_value_exits_two() {
    let (_dir, path) = planted_fixture();
    let (code, _stdout, stderr) = scan(&path, &["--format", "yaml"]);
    assert_eq!(
        code,
        Some(2),
        "an unknown --format value is a user error → exit 2; stderr={stderr}"
    );
}

#[test]
fn out_of_range_min_confidence_exits_two() {
    let (_dir, path) = planted_fixture();
    // Both ends of the [0.0, 1.0] interval are rejected with a precise message.
    for bad in ["-0.1", "1.5", "2.0", "nan"] {
        let (code, _stdout, stderr) = scan(&path, &["--min-confidence", bad]);
        assert_eq!(
            code,
            Some(2),
            "--min-confidence {bad} is out of range → exit 2; stderr={stderr}"
        );
    }
}

#[test]
fn short_f_is_not_a_format_alias_and_exits_two() {
    // `--format` has NO `-f` short (it would collide with future flags); a
    // script that assumes `-f json` must fail loudly, not be misparsed.
    let (_dir, path) = planted_fixture();
    let (code, _stdout, _stderr) = scan(&path, &["-f", "json"]);
    assert_eq!(code, Some(2), "`-f` is not a valid scan flag → exit 2");
}

// ----------------------------------------------------------------------------
// BACKEND × FORMAT GRID  (recall must not depend on the flag combination)
// ----------------------------------------------------------------------------

#[test]
fn every_backend_surfaces_the_planted_secret_under_json() {
    let (_dir, path) = planted_fixture();
    // Compute the reference hash set once via the default route.
    let reference = json_hashes(&scan(&path, &["--format", "json"]).1);
    assert!(
        !reference.is_empty(),
        "reference scan must surface the planted finding"
    );
    for &backend in BACKENDS {
        let (code, stdout, stderr) = scan(&path, &["--backend", backend, "--format", "json"]);
        assert_eq!(
            code,
            Some(1),
            "--backend {backend} scan of the planted secret must exit 1; stderr={stderr}"
        );
        let ids = json_detector_ids(&stdout);
        assert!(
            ids.contains(DETECTOR_ID),
            "--backend {backend} must surface {DETECTOR_ID}; got ids={ids:?}"
        );
        assert_eq!(
            json_hashes(&stdout),
            reference,
            "--backend {backend} must surface the SAME credential hash as the default \
             route (backend choice must never change recall); stdout={stdout}"
        );
    }
}

#[test]
fn every_format_parses_and_carries_the_planted_finding() {
    let (_dir, path) = planted_fixture();
    for &format in FORMATS {
        let (code, stdout, stderr) = scan(&path, &["--format", format]);
        assert_eq!(
            code,
            Some(1),
            "--format {format} scan of the planted secret must exit 1; stderr={stderr}"
        );
        match format {
            "json" => {
                let ids = json_detector_ids(&stdout);
                assert!(
                    ids.contains(DETECTOR_ID),
                    "json must carry {DETECTOR_ID}; got {ids:?}"
                );
            }
            "jsonl" => {
                let any = parse_jsonl_objects(&stdout, "format matrix JSONL report")
                    .into_iter()
                    .any(|f| f.get("detector_id").and_then(|d| d.as_str()) == Some(DETECTOR_ID));
                assert!(
                    any,
                    "jsonl must carry one {DETECTOR_ID} object; got {stdout}"
                );
            }
            "sarif" => {
                let v: serde_json::Value =
                    serde_json::from_str(stdout.trim()).expect("sarif is valid JSON");
                assert_eq!(v["version"], "2.1.0", "sarif version must be 2.1.0");
                let results = v["runs"][0]["results"]
                    .as_array()
                    .expect("sarif runs[0].results");
                assert!(
                    results
                        .iter()
                        .any(|r| r["ruleId"].as_str() == Some(DETECTOR_ID)),
                    "sarif must carry a result with ruleId {DETECTOR_ID}; got {stdout}"
                );
            }
            "csv" => {
                assert!(
                    stdout.starts_with(
                        "detector_id,detector_name,service,severity,credential_redacted,"
                    ),
                    "csv must start with the documented header row; got {stdout}"
                );
                assert!(
                    stdout.contains(&format!(
                        "{DETECTOR_ID},GitHub Classic PAT,github,{SEVERITY},"
                    )),
                    "csv must carry the planted finding row; got {stdout}"
                );
            }
            "junit" => {
                assert!(
                    stdout.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                        && stdout.contains("<testsuites>")
                        && stdout.contains(DETECTOR_ID),
                    "junit must be well-formed XML naming {DETECTOR_ID}; got {stdout}"
                );
            }
            "html" => {
                assert!(
                    stdout.starts_with("<!DOCTYPE html>") && stdout.contains("</html>"),
                    "html must be a complete document; got first 120 bytes: {}",
                    &stdout.chars().take(120).collect::<String>()
                );
            }
            "text" => {
                assert!(
                    stdout.contains("GitHub Classic PAT") && stdout.contains(REDACTED),
                    "text must name the detector and the redacted token; got {stdout}"
                );
            }
            other => panic!("unhandled format in grid: {other}"),
        }
    }
}

#[test]
fn json_and_jsonl_surface_identical_hashes_across_every_backend() {
    // The full grid corner that matters most: for EVERY backend, the JSON and
    // JSONL serializers must agree on the finding set (a per-format reporter
    // bug is invisible until you diff the two structured forms).
    let (_dir, path) = planted_fixture();
    for &backend in BACKENDS {
        let json = json_hashes(&scan(&path, &["--backend", backend, "--format", "json"]).1);
        let jsonl_out = scan(&path, &["--backend", backend, "--format", "jsonl"]).1;
        let jsonl: BTreeSet<String> =
            parse_jsonl_objects(&jsonl_out, "backend matrix JSONL report")
                .into_iter()
                .filter_map(|f| {
                    f.get("credential_hash")
                        .and_then(|h| h.as_str())
                        .map(String::from)
                })
                .collect();
        assert_eq!(
            json, jsonl,
            "--backend {backend}: json and jsonl must surface identical hashes"
        );
        assert!(
            !json.is_empty(),
            "--backend {backend}: hashes must be present"
        );
    }
}

// ----------------------------------------------------------------------------
// MASKING + OUTPUT FILE + SEVERITY + HERMETIC
// ----------------------------------------------------------------------------

#[test]
fn default_redacts_and_show_secrets_reveals_the_full_token() {
    let (_dir, path) = planted_fixture();

    let masked = scan(&path, &["--format", "json"]).1;
    let v: serde_json::Value = serde_json::from_str(&masked).expect("json");
    assert_eq!(
        v[0]["credential_redacted"].as_str(),
        Some(REDACTED),
        "default scan must redact the token to {REDACTED}; got {masked}"
    );
    assert!(
        !masked.contains(PLANTED),
        "default scan must NOT leak the full token; got {masked}"
    );

    let shown = scan(&path, &["--format", "json", "--show-secrets"]).1;
    assert!(
        shown.contains(PLANTED),
        "--show-secrets must reveal the full token; got {shown}"
    );
}

#[test]
fn output_flag_writes_report_to_file_and_leaves_stdout_empty() {
    let (dir, path) = planted_fixture();
    let out = dir.path().join("report.json");
    for flag in ["-o", "--output"] {
        let _ = std::fs::remove_file(&out);
        let (code, stdout, stderr) =
            scan(&path, &["--format", "json", flag, out.to_str().unwrap()]);
        assert_eq!(
            code,
            Some(1),
            "scan with {flag} of a planted secret must still exit 1; stderr={stderr}"
        );
        assert!(
            stdout.trim().is_empty(),
            "with {flag} the report goes to the file, not stdout; stdout={stdout:?}"
        );
        let written = std::fs::read_to_string(&out)
            .unwrap_or_else(|e| panic!("{flag} must create the report file: {e}"));
        let ids = json_detector_ids(&written);
        assert!(
            ids.contains(DETECTOR_ID),
            "{flag} file must contain the planted finding; got {written}"
        );
    }
}

#[test]
fn severity_filter_keeps_a_critical_finding_and_a_higher_floor_does_not_drop_a_checksum_finding() {
    let (_dir, path) = planted_fixture();
    // The planted PAT is `critical`; `--severity critical` keeps it.
    let crit = scan(&path, &["--format", "json", "--severity", "critical"]);
    assert_eq!(
        crit.0,
        Some(1),
        "critical filter must keep the critical PAT"
    );
    assert!(
        json_detector_ids(&crit.1).contains(DETECTOR_ID),
        "critical filter must keep {DETECTOR_ID}; got {}",
        crit.1
    );

    // A checksum-valid PAT is boosted to the confidence floor, so even
    // `--min-confidence 1.0` keeps it (pin that exact behavior).
    let strict = scan(&path, &["--format", "json", "--min-confidence", "1.0"]);
    assert_eq!(
        strict.0,
        Some(1),
        "a checksum-valid PAT survives --min-confidence 1.0; stderr={}",
        strict.2
    );
    let v: serde_json::Value = serde_json::from_str(&strict.1).expect("json");
    assert_eq!(
        v[0]["confidence"].as_f64(),
        Some(1.0),
        "the surviving finding reports confidence 1.0 at the max floor; got {}",
        strict.1
    );
}

#[test]
fn min_confidence_boundary_values_zero_and_one_are_accepted() {
    let (_dir, path) = planted_fixture();
    for mc in ["0", "0.0", "0.40", "1", "1.0"] {
        let (code, _stdout, stderr) = scan(&path, &["--min-confidence", mc, "--format", "json"]);
        assert_eq!(
            code,
            Some(1),
            "--min-confidence {mc} is in range and must scan (exit 1 on the planted secret); stderr={stderr}"
        );
    }
}

#[test]
fn no_config_runs_hermetically_and_finds_the_planted_secret() {
    // `--no-config` must scan on the shipped defaults (no walk-up `.keyhog.toml`)
    // and still surface the planted finding (the benchmark/CI hermetic path).
    let (_dir, path) = planted_fixture();
    let (code, stdout, stderr) = scan(&path, &["--no-config", "--format", "json"]);
    assert_eq!(
        code,
        Some(1),
        "--no-config scan must exit 1; stderr={stderr}"
    );
    assert!(
        json_detector_ids(&stdout).contains(DETECTOR_ID),
        "--no-config must still find {DETECTOR_ID}; got {stdout}"
    );
}

#[test]
fn no_config_and_config_are_mutually_exclusive_exit_two() {
    let (_dir, path) = planted_fixture();
    let (code, _stdout, stderr) = scan(&path, &["--no-config", "--config", "/tmp/whatever.toml"]);
    assert_eq!(
        code,
        Some(2),
        "--no-config conflicts with --config → exit 2; stderr={stderr}"
    );
}

#[test]
fn stdin_scan_finds_the_planted_secret() {
    // The always-on stdin path (no source feature needed) must work end to end.
    let mut cmd = Command::new(binary());
    cmd.args([
        "scan",
        "--daemon=off",
        "--backend",
        "simd",
        "--stdin",
        "--format",
        "json",
    ]);
    cmd.env_remove("KEYHOG_BACKEND");
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("spawn keyhog scan --stdin");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin handle");
        write!(stdin, "API={PLANTED}\n").expect("write to stdin");
    }
    let out = child.wait_with_output().expect("wait keyhog");
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdin scan of a planted secret must exit 1; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        json_detector_ids(&stdout).contains(DETECTOR_ID),
        "stdin scan must find {DETECTOR_ID}; got {stdout}"
    );
}
