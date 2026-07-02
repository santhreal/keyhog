//! Regression e2e — the `scan` BASELINE surfaces (`--create-baseline`,
//! `--baseline`, `--update-baseline`), driven over the SHIPPED `keyhog` binary
//! and pinned to EXACT values, plus SARIF `partialFingerprints` stability across
//! runs and its cross-surface agreement with the baseline credential hash.
//!
//! This file is DISTINCT from `regression_cli_diff_baseline_depth.rs`, which
//! drives the standalone `keyhog diff <before> <after>` subcommand over two
//! prebuilt baseline JSON docs. Here we drive the SCAN-time baseline pipeline:
//!   * `--create-baseline PATH` snapshots current findings to a v1 JSON file and
//!     exits 0 without emitting a findings report (orchestrator/run.rs returns
//!     early);
//!   * `--baseline PATH` suppresses any finding whose `(detector_id,
//!     credential_hash)` pair is already acknowledged — an all-suppressed scan
//!     exits 0 with an empty `[]` report, while a NEW pair surfaces and exits 1;
//!   * `--update-baseline PATH` merges new findings into (or creates) the file,
//!     growing the entry set and deduping by the identity pair;
//!   * a malformed / wrong-version baseline fed to `--baseline` fails CLOSED
//!     (exit 2), never silently scanning without suppression.
//!
//! HOST-INDEPENDENCE: every scan pins `--backend cpu` (the always-available,
//! feature-independent engine) and clears `KEYHOG_BACKEND`, and every planted
//! secret is an AC-literal-anchored detector (`github-classic-pat` via `ghp_`,
//! `aws-access-key` via `AKIA`) that fires on the scalar/CPU path — no
//! accelerator is ever assumed. No assertion uses `is_empty()` / `is_ok()` /
//! `len() > 0` as its only check (Law 6).

use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A GitHub classic PAT with a VALID CRC32 tail — fires `github-classic-pat` at
/// confidence 0.9 with a passing checksum, so it survives the confidence floor
/// on the CPU backend. Split-literal so this file is not itself a planted secret
/// for keyhog's own self-scan.
const PAT: &str = concat!("ghp_", "1234567890123456789012345678902PDSiF");
const PAT_DETECTOR: &str = "github-classic-pat";

/// An AWS access-key id (AC-literal `AKIA` detector) that fires on the CPU path.
const AWS: &str = concat!("AKIA", "QYLPMN5HFIQR7XYA");
const AWS_DETECTOR: &str = "aws-access-key";

/// The exact SARIF `partialFingerprints` key the reporter emits (versioned).
const FP_KEY: &str = "keyhog/credentialHash/v1";

/// Run `keyhog scan --no-daemon --backend cpu <extra…> <path>` hermetically and
/// return (exit-code, stdout, stderr). Clears `KEYHOG_BACKEND` so the flag is
/// the only routing input; `NO_COLOR` keeps stderr progress plain.
fn scan(path: &Path, extra: &[&str]) -> (Option<i32>, String, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--no-daemon", "--backend", "cpu"]);
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

/// A tempdir holding one file `name` with `body`. Returns (dir-guard, file-path).
fn file_with(name: &str, body: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join(name);
    std::fs::write(&path, body).expect("write fixture");
    (dir, path)
}

/// Parse a JSON report / baseline document, panicking with raw bytes on failure.
fn json_of(s: &str) -> serde_json::Value {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("not JSON ({e}):\n{s}"))
}

/// Load and parse a written baseline file at `path`.
fn read_baseline(path: &Path) -> serde_json::Value {
    let raw = std::fs::read_to_string(path).expect("read baseline file");
    json_of(&raw)
}

/// The `credential_hash` strings of the baseline's entries, sorted.
fn baseline_hashes(v: &serde_json::Value) -> Vec<String> {
    v["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .map(|e| e["credential_hash"].as_str().expect("hash str").to_string())
        .collect()
}

/// The `detector_id` strings of the baseline's entries, in file order.
fn baseline_detectors(v: &serde_json::Value) -> Vec<String> {
    v["entries"]
        .as_array()
        .expect("entries array")
        .iter()
        .map(|e| e["detector_id"].as_str().expect("id str").to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// --create-baseline — writes a v1 file, exits 0, records the identity pair
// ---------------------------------------------------------------------------

/// Scanning a single planted PAT with `--create-baseline` writes a version-1
/// document with exactly one entry carrying the detector id, and exits 0 (the
/// create path returns before the findings report / findings exit code).
#[test]
fn create_baseline_writes_v1_one_entry_and_exits_zero() {
    let (_d, f) = file_with("secrets.env", &format!("{PAT}\n"));
    let base = _d.path().join("baseline.json");
    let (code, _out, err) = scan(&f, &["--create-baseline", base.to_str().unwrap()]);
    assert_eq!(
        code,
        Some(0),
        "--create-baseline returns early with exit 0 even with findings; stderr={err}"
    );

    let v = read_baseline(&base);
    assert_eq!(
        v["version"].as_u64(),
        Some(1),
        "a created baseline must be version 1; got {v}"
    );
    let entries = v["entries"].as_array().expect("entries array");
    assert_eq!(entries.len(), 1, "exactly one PAT → one entry; got {v}");
    assert_eq!(
        entries[0]["detector_id"].as_str(),
        Some(PAT_DETECTOR),
        "the entry must carry the github-classic-pat id; got {v}"
    );
}

/// The baseline `credential_hash` is the `sha256:`-prefixed, 64-hex-char form
/// (the baseline-specific spelling documented in baseline.rs::baseline_hash_key).
#[test]
fn create_baseline_hash_is_sha256_prefixed_64_hex() {
    let (_d, f) = file_with("secrets.env", &format!("{PAT}\n"));
    let base = _d.path().join("baseline.json");
    let (code, _o, _e) = scan(&f, &["--create-baseline", base.to_str().unwrap()]);
    assert_eq!(code, Some(0));

    let v = read_baseline(&base);
    let hashes = baseline_hashes(&v);
    assert_eq!(hashes.len(), 1, "one hash; got {v}");
    let h = &hashes[0];
    let hex = h
        .strip_prefix("sha256:")
        .unwrap_or_else(|| panic!("hash must be sha256:-prefixed; got {h}"));
    assert_eq!(
        hex.len(),
        64,
        "sha256 hex body must be 64 chars; got {hex:?}"
    );
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "hash body must be lowercase hex; got {hex:?}"
    );
}

/// The baseline entry records the finding's file path and 1-indexed line for
/// reference: the token planted on line 2 (comment on line 1) yields `line: 2`
/// and a `file_path` naming the fixture.
#[test]
fn create_baseline_records_file_path_and_line_two() {
    let body = format!("# leading comment line\n{PAT}\n");
    let (_d, f) = file_with("app.env", &body);
    let base = _d.path().join("baseline.json");
    let (code, _o, _e) = scan(&f, &["--create-baseline", base.to_str().unwrap()]);
    assert_eq!(code, Some(0));

    let v = read_baseline(&base);
    let e = &v["entries"][0];
    assert_eq!(
        e["line"].as_u64(),
        Some(2),
        "the token is on line 2 (1-indexed); got {v}"
    );
    let fp = e["file_path"].as_str().expect("file_path present");
    assert!(
        fp.ends_with("app.env"),
        "file_path must name the fixture app.env; got {fp}"
    );
}

/// A file carrying TWO distinct secrets yields a 2-entry baseline, sorted by
/// `detector_id` (from_findings sorts): `aws-access-key` precedes
/// `github-classic-pat`.
#[test]
fn create_baseline_multi_entry_sorted_by_detector_id() {
    let body = format!("{AWS}\n{PAT}\n");
    let (_d, f) = file_with("multi.env", &body);
    let base = _d.path().join("baseline.json");
    let (code, _o, err) = scan(&f, &["--create-baseline", base.to_str().unwrap()]);
    assert_eq!(code, Some(0), "stderr={err}");

    let v = read_baseline(&base);
    let ids = baseline_detectors(&v);
    assert_eq!(
        ids,
        vec![AWS_DETECTOR.to_string(), PAT_DETECTOR.to_string()],
        "two entries sorted by detector id (aws before github); got {v}"
    );
}

// ---------------------------------------------------------------------------
// --baseline — suppresses the acknowledged pair, surfaces new pairs
// ---------------------------------------------------------------------------

/// Re-scanning the SAME file whose finding is already in the baseline suppresses
/// it entirely: the JSON report is exactly `[]` and the scan exits 0 (no new
/// entries → no findings exit code).
#[test]
fn baseline_suppresses_known_finding_exit_zero_empty_report() {
    let (_d, f) = file_with("secrets.env", &format!("{PAT}\n"));
    let base = _d.path().join("baseline.json");
    let (c0, _o, _e) = scan(&f, &["--create-baseline", base.to_str().unwrap()]);
    assert_eq!(c0, Some(0));

    let (code, out, err) = scan(
        &f,
        &["--baseline", base.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(
        code,
        Some(0),
        "an all-baselined scan has no new findings → exit 0; stderr={err}"
    );
    assert_eq!(
        out.trim(),
        "[]",
        "the suppressed report must be exactly the empty array; got {out}"
    );
}

/// An EMPTY baseline (created from a clean file with no secrets) acknowledges
/// nothing, so a subsequent scan of the PAT file surfaces the finding and exits
/// 1 with the PAT present in the report.
#[test]
fn empty_baseline_surfaces_finding_exit_one() {
    let (clean_d, clean) = file_with("clean.txt", "nothing to see here\n");
    let base = clean_d.path().join("empty-baseline.json");
    let (c0, _o, _e) = scan(&clean, &["--create-baseline", base.to_str().unwrap()]);
    assert_eq!(c0, Some(0));
    // The clean baseline must genuinely be empty.
    let v0 = read_baseline(&base);
    assert_eq!(
        v0["entries"].as_array().expect("entries").len(),
        0,
        "a clean scan produces a zero-entry baseline; got {v0}"
    );

    let (_pd, pf) = file_with("secrets.env", &format!("{PAT}\n"));
    let (code, out, err) = scan(
        &pf,
        &["--baseline", base.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(
        code,
        Some(1),
        "an unacknowledged finding surfaces → exit 1 (EXIT_FINDINGS); stderr={err}"
    );
    let report = json_of(&out);
    let arr = report.as_array().expect("json report array");
    assert_eq!(arr.len(), 1, "exactly the one un-baselined PAT; got {out}");
    assert_eq!(
        arr[0]["detector_id"].as_str(),
        Some(PAT_DETECTOR),
        "the surfaced finding is the PAT; got {out}"
    );
}

/// A baseline built from a PAT-only tree suppresses the PAT but NOT a newly
/// introduced AWS key in the same tree: the report holds exactly the AWS finding
/// (github filtered out) and the scan exits 1.
#[test]
fn baseline_suppresses_pat_but_surfaces_new_aws_exit_one() {
    let dir = TempDir::new().expect("tempdir");
    let pat_file = dir.path().join("a.env");
    std::fs::write(&pat_file, format!("{PAT}\n")).expect("write pat");
    let base = dir.path().join("baseline.json");

    // Baseline snapshots the tree while it holds ONLY the PAT.
    let (c0, _o, _e) = scan(dir.path(), &["--create-baseline", base.to_str().unwrap()]);
    assert_eq!(c0, Some(0));
    assert_eq!(
        read_baseline(&base)["entries"]
            .as_array()
            .expect("entries")
            .len(),
        1,
        "baseline snapshots only the PAT at create time"
    );

    // Now introduce a NEW AWS key and re-scan the whole tree against the baseline.
    let aws_file = dir.path().join("b.env");
    std::fs::write(&aws_file, format!("{AWS}\n")).expect("write aws");

    let (code, out, err) = scan(
        dir.path(),
        &["--baseline", base.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(
        code,
        Some(1),
        "the new AWS pair is unacknowledged → exit 1; stderr={err}"
    );
    let report = json_of(&out);
    let ids: Vec<&str> = report
        .as_array()
        .expect("json array")
        .iter()
        .filter_map(|f| f["detector_id"].as_str())
        .collect();
    assert!(
        ids.contains(&AWS_DETECTOR),
        "the new AWS finding must surface; got {out}"
    );
    assert!(
        !ids.contains(&PAT_DETECTOR),
        "the baselined PAT must stay suppressed; got {out}"
    );
}

/// Suppression matches on the `(detector_id, credential_hash)` PAIR, NOT the file
/// path or line — the baseline docs say secrets may move. A PAT baselined from
/// file A stays suppressed when the same secret reappears in a DIFFERENT file at
/// a DIFFERENT line: exit 0, empty report.
#[test]
fn baseline_suppression_is_path_independent() {
    let (_ad, a) = file_with("a.env", &format!("{PAT}\n"));
    let base = _ad.path().join("baseline.json");
    let (c0, _o, _e) = scan(&a, &["--create-baseline", base.to_str().unwrap()]);
    assert_eq!(c0, Some(0));

    // Same secret, different file name AND different line (shifted down by 3).
    let (_bd, b) = file_with("elsewhere.txt", &format!("l1\nl2\nl3\n{PAT}\n"));
    let (code, out, err) = scan(
        &b,
        &["--baseline", base.to_str().unwrap(), "--format", "json"],
    );
    assert_eq!(
        code,
        Some(0),
        "same (detector,hash) pair stays suppressed across path/line moves; stderr={err}"
    );
    assert_eq!(
        out.trim(),
        "[]",
        "the moved-but-baselined secret must not surface; got {out}"
    );
}

// ---------------------------------------------------------------------------
// --update-baseline — creates-if-absent, merges, dedups
// ---------------------------------------------------------------------------

/// `--update-baseline` against a non-existent path creates it: the first run
/// records the PAT as a NEW entry (exit 1), and an immediate re-run finds it
/// already acknowledged (exit 0) with the entry count unchanged (dedup).
#[test]
fn update_baseline_creates_then_dedups_on_rerun() {
    let (_d, f) = file_with("secrets.env", &format!("{PAT}\n"));
    let base = _d.path().join("evolving-baseline.json");
    assert!(!base.exists(), "baseline must not pre-exist");

    let (c1, _o1, e1) = scan(&f, &["--update-baseline", base.to_str().unwrap()]);
    assert_eq!(
        c1,
        Some(1),
        "first update records a NEW entry → exit 1; stderr={e1}"
    );
    let v1 = read_baseline(&base);
    assert_eq!(
        v1["entries"].as_array().expect("entries").len(),
        1,
        "first update writes exactly one entry; got {v1}"
    );

    let (c2, _o2, e2) = scan(&f, &["--update-baseline", base.to_str().unwrap()]);
    assert_eq!(
        c2,
        Some(0),
        "the PAT is now acknowledged → no new entries → exit 0; stderr={e2}"
    );
    let v2 = read_baseline(&base);
    assert_eq!(
        v2["entries"].as_array().expect("entries").len(),
        1,
        "re-running must not duplicate the entry (dedup by pair); got {v2}"
    );
}

/// A second `--update-baseline` after a NEW secret appears GROWS the file from 1
/// to 2 entries and exits 1 (the AWS key is new), while the original PAT entry is
/// preserved.
#[test]
fn update_baseline_grows_and_preserves_existing() {
    let dir = TempDir::new().expect("tempdir");
    let pat_file = dir.path().join("a.env");
    std::fs::write(&pat_file, format!("{PAT}\n")).expect("write pat");
    let base = dir.path().join("baseline.json");

    let (c1, _o1, _e1) = scan(dir.path(), &["--update-baseline", base.to_str().unwrap()]);
    assert_eq!(c1, Some(1), "first update: PAT is new → exit 1");
    assert_eq!(
        read_baseline(&base)["entries"]
            .as_array()
            .expect("entries")
            .len(),
        1
    );

    let aws_file = dir.path().join("b.env");
    std::fs::write(&aws_file, format!("{AWS}\n")).expect("write aws");

    let (c2, _o2, e2) = scan(dir.path(), &["--update-baseline", base.to_str().unwrap()]);
    assert_eq!(
        c2,
        Some(1),
        "second update: AWS is new → exit 1; stderr={e2}"
    );
    let v = read_baseline(&base);
    let ids = baseline_detectors(&v);
    assert_eq!(ids.len(), 2, "the file grew to two entries; got {v}");
    assert!(
        ids.contains(&AWS_DETECTOR.to_string()) && ids.contains(&PAT_DETECTOR.to_string()),
        "both the preserved PAT and the new AWS entry must be present; got {v}"
    );
}

// ---------------------------------------------------------------------------
// fail-closed — malformed / wrong-version baseline handed to --baseline
// ---------------------------------------------------------------------------

/// Feeding a `scan --format json` FINDINGS report (a top-level JSON array) to
/// `--baseline` fails CLOSED: exit 2 (EXIT_USER_ERROR) with the actionable
/// `--create-baseline` hint — it must NOT silently scan without suppression.
#[test]
fn baseline_findings_report_fails_closed_exit_two() {
    let (_d, f) = file_with("secrets.env", &format!("{PAT}\n"));
    let bad = _d.path().join("findings-report.json");
    std::fs::write(
        &bad,
        r#"[{"detector_id":"github-classic-pat","credential_redacted":"ghp_...DSiF"}]"#,
    )
    .expect("write findings report");

    let (code, _out, err) = scan(&f, &["--baseline", bad.to_str().unwrap()]);
    assert_eq!(
        code,
        Some(2),
        "a findings report is not a baseline → user error → exit 2; stderr={err}"
    );
    assert!(
        err.contains("--create-baseline"),
        "the error must point at --create-baseline to fix it; got {err}"
    );
}

/// A syntactically valid baseline carrying an UNSUPPORTED version handed to
/// `--baseline` fails CLOSED at load: exit 2 and the error names the seen and
/// expected version numbers.
#[test]
fn baseline_unsupported_version_fails_closed_exit_two() {
    let (_d, f) = file_with("secrets.env", &format!("{PAT}\n"));
    let bad = _d.path().join("v999-baseline.json");
    std::fs::write(&bad, r#"{"version": 999, "created": "t", "entries": []}"#).expect("write v999");

    let (code, _out, err) = scan(&f, &["--baseline", bad.to_str().unwrap()]);
    assert_eq!(
        code,
        Some(2),
        "an unsupported baseline version is a user error → exit 2; stderr={err}"
    );
    assert!(
        err.contains("unsupported baseline version 999") && err.contains("expected 1"),
        "the error must state seen version 999 and expected 1; got {err}"
    );
}

/// The three baseline modes are mutually exclusive (clap `conflicts_with_all`):
/// `--baseline X --create-baseline Y` is a usage error → clap exit 2.
#[test]
fn baseline_and_create_baseline_conflict_exit_two() {
    let (_d, f) = file_with("secrets.env", &format!("{PAT}\n"));
    let (code, _out, err) = scan(&f, &["--baseline", "b.json", "--create-baseline", "c.json"]);
    assert_eq!(
        code,
        Some(2),
        "conflicting baseline flags are a clap usage error → exit 2; stderr={err}"
    );
    assert!(
        err.contains("cannot be used with"),
        "clap must report the flag conflict; got {err}"
    );
}

// ---------------------------------------------------------------------------
// SARIF partialFingerprints — stability across runs + baseline agreement
// ---------------------------------------------------------------------------

/// The SARIF `partialFingerprints["keyhog/credentialHash/v1"]` is STABLE: two
/// independent scans of the same secret produce byte-identical fingerprints (the
/// value GitHub code-scanning dedups alerts on across runs).
#[test]
fn sarif_fingerprint_stable_across_two_runs() {
    let (_d, f) = file_with("secrets.env", &format!("{PAT}\n"));

    let fp_of = |path: &Path| -> String {
        let (_c, out, _e) = scan(path, &["--format", "sarif"]);
        let v = json_of(&out);
        v.pointer("/runs/0/results/0/partialFingerprints")
            .and_then(|p| p.get(FP_KEY))
            .and_then(|h| h.as_str())
            .unwrap_or_else(|| panic!("missing partialFingerprints[{FP_KEY}] in:\n{out}"))
            .to_string()
    };

    let first = fp_of(&f);
    let second = fp_of(&f);
    assert_eq!(
        first.len(),
        64,
        "the credential fingerprint is a 64-hex sha256; got {first:?}"
    );
    assert_eq!(
        first, second,
        "the same secret must yield a byte-identical fingerprint across runs"
    );
}

/// Cross-surface truth: the SARIF fingerprint (bare hex) equals the baseline
/// `credential_hash` with its `sha256:` prefix stripped — the two identity
/// surfaces describe the exact same credential hash and must never drift.
#[test]
fn sarif_fingerprint_equals_baseline_hash_body() {
    let (_d, f) = file_with("secrets.env", &format!("{PAT}\n"));

    // Baseline surface: sha256:-prefixed hex.
    let base = _d.path().join("baseline.json");
    let (c0, _o, _e) = scan(&f, &["--create-baseline", base.to_str().unwrap()]);
    assert_eq!(c0, Some(0));
    let baseline_hash = baseline_hashes(&read_baseline(&base))
        .into_iter()
        .next()
        .expect("one baseline hash");
    let baseline_body = baseline_hash
        .strip_prefix("sha256:")
        .expect("sha256: prefix")
        .to_string();

    // SARIF surface: bare hex.
    let (_c, out, _e2) = scan(&f, &["--format", "sarif"]);
    let v = json_of(&out);
    let sarif_fp = v
        .pointer("/runs/0/results/0/partialFingerprints")
        .and_then(|p| p.get(FP_KEY))
        .and_then(|h| h.as_str())
        .unwrap_or_else(|| panic!("missing partialFingerprints in:\n{out}"))
        .to_string();

    assert_eq!(
        sarif_fp, baseline_body,
        "SARIF fingerprint and baseline hash body must be the same 64-hex sha256"
    );
}
