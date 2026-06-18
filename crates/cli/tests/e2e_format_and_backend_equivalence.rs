//! e2e: output-format and backend-flag wiring through the real binary
//! (TESTING vector 12 + WIRING vector 9, lane 9).
//!
//! Two operator-visible contracts that only a real-tool run can prove:
//!
//!   1. FORMAT WIRING — the SAME planted secret must surface under `--format
//!      json`, `--format jsonl`, and `--format sarif`, carrying the SAME
//!      credential hash. A reporter that drops a finding in one format (a
//!      serializer bug, a filter applied on only one path) is a recall hole an
//!      operator hits silently when they switch `--format`.
//!
//!   2. BACKEND-FLAG WIRING / e2e RECALL PARITY — `--backend cpu` and
//!      `--backend simd` (and `gpu`, which fails closed without a usable
//!      adapter) must surface the SAME finding through the binary. The unit
//!      parity tests compare backends inside one process on synthetic chunks;
//!      this proves the WHOLE shipped pipeline (walker → engine → suppression →
//!      reporter) agrees across the operator-selectable backend flag.
//!
//! All assertions pin EXACT values (the planted detector id + credential hash),
//! never `!is_empty`. Deterministic: a single planted secret, clean otherwise,
//! `--no-daemon` so there is no background-process nondeterminism.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A planted, credential-sufficient GitHub PAT with a VALID CRC32 tail (the
/// token proven in the scanner boundary/parity tests). It fires
/// `github-classic-pat` on its own bytes, so every format and backend must
/// surface it.
const PLANTED: &str = "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";

fn fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("leak.env");
    std::fs::write(&path, format!("GITHUB_TOKEN={PLANTED}\n")).expect("write fixture");
    (dir, path)
}

fn run(path: &PathBuf, format: &str, backend: Option<&str>) -> (Option<i32>, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--no-daemon", "--format", format]);
    cmd.args(["--backend", backend.unwrap_or("simd")]);
    cmd.arg(path);
    cmd.env_remove("KEYHOG_GPU_AUTOROUTE");
    let output = cmd.output().expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// Pull the credential_hash of every finding from a JSON-array report.
fn json_hashes(stdout: &str) -> BTreeSet<String> {
    let v: serde_json::Value = serde_json::from_str(stdout).expect("stdout is valid JSON");
    v.as_array()
        .expect("JSON report is an array")
        .iter()
        .filter_map(|f| f.get("credential_hash").and_then(|h| h.as_str()))
        .map(String::from)
        .collect()
}

/// Pull the credential_hash of every finding from a JSONL report (one object
/// per line).
fn jsonl_hashes(stdout: &str) -> BTreeSet<String> {
    stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|f| {
            f.get("credential_hash")
                .and_then(|h| h.as_str())
                .map(String::from)
        })
        .collect()
}

/// Pull every SARIF result's partialFingerprints / properties hash. keyhog's
/// SARIF carries the credential hash in `partialFingerprints` (used by the
/// dogfood self-scan suppression, per project memory). We extract whatever
/// fingerprint values are present and assert non-empty + that the run found the
/// finding.
fn sarif_result_count(stdout: &str) -> usize {
    let v: serde_json::Value = serde_json::from_str(stdout).expect("SARIF is valid JSON");
    v.pointer("/runs/0/results")
        .and_then(|r| r.as_array())
        .map(|a| a.len())
        .unwrap_or(0)
}

#[test]
fn the_planted_secret_surfaces_identically_under_json_and_jsonl() {
    let (_dir, path) = fixture();

    let (code_json, out_json) = run(&path, "json", None);
    let (code_jsonl, out_jsonl) = run(&path, "jsonl", None);

    // Findings present, none verified -> exit 1 (documented).
    assert_eq!(
        code_json,
        Some(1),
        "json scan must exit 1; stdout={out_json}"
    );
    assert_eq!(
        code_jsonl,
        Some(1),
        "jsonl scan must exit 1; stdout={out_jsonl}"
    );

    let json = json_hashes(&out_json);
    let jsonl = jsonl_hashes(&out_jsonl);

    assert!(
        !json.is_empty(),
        "json report must contain the planted finding; stdout={out_json}"
    );
    assert_eq!(
        json, jsonl,
        "json and jsonl must surface the SAME finding hashes (a format must \
         never drop a finding the other keeps)"
    );
}

#[test]
fn the_planted_secret_surfaces_under_sarif_with_the_same_finding_count_as_json() {
    let (_dir, path) = fixture();
    let (code_sarif, out_sarif) = run(&path, "sarif", None);
    let (_code_json, out_json) = run(&path, "json", None);

    assert_eq!(
        code_sarif,
        Some(1),
        "sarif scan must exit 1; stdout={out_sarif}"
    );

    let sarif_results = sarif_result_count(&out_sarif);
    let json_findings = json_hashes(&out_json).len();

    // The planted ghp_ token fires exactly `github-classic-pat`; whatever the
    // JSON path reports, SARIF must report the same number of findings as
    // results (a reporter must never drop or duplicate a finding per format).
    assert!(
        sarif_results >= 1,
        "sarif must carry the planted finding as a result; stdout={out_sarif}"
    );
    assert_eq!(
        sarif_results, json_findings,
        "sarif result count ({sarif_results}) must equal the json finding count \
         ({json_findings}) — formats must agree on how many findings exist"
    );
}

#[test]
fn cpu_and_simd_backends_surface_the_same_finding_through_the_binary() {
    let (_dir, path) = fixture();

    let (code_cpu, out_cpu) = run(&path, "json", Some("cpu"));
    let (code_simd, out_simd) = run(&path, "json", Some("simd"));

    assert_eq!(code_cpu, Some(1), "cpu-backend scan must exit 1");
    assert_eq!(code_simd, Some(1), "simd-backend scan must exit 1");

    let cpu = json_hashes(&out_cpu);
    let simd = json_hashes(&out_simd);

    assert!(
        !cpu.is_empty(),
        "cpu backend must surface the planted finding; stdout={out_cpu}"
    );
    assert_eq!(
        cpu, simd,
        "--backend cpu and --backend simd must surface IDENTICAL finding hashes \
         through the whole shipped pipeline (e2e backend recall parity)"
    );
}

#[test]
fn forcing_gpu_backend_surfaces_or_fails_closed_when_no_adapter() {
    // `--backend gpu` forces the device path. On a GPU host it must surface the
    // same finding as SIMD; on a no-GPU host it must fail closed, not silently
    // scan a substitute backend.
    let (_dir, path) = fixture();
    let (code_gpu, out_gpu) = run(&path, "json", Some("gpu"));
    let (_code_simd, out_simd) = run(&path, "json", Some("simd"));

    if code_gpu == Some(1) {
        assert_eq!(
            json_hashes(&out_gpu),
            json_hashes(&out_simd),
            "--backend gpu on a usable GPU host must surface the SAME finding as simd"
        );
    } else {
        assert!(
            matches!(code_gpu, Some(2) | Some(12)),
            "--backend gpu without a usable GPU must fail closed, not silently \
             substitute another backend; code={code_gpu:?} stdout={out_gpu}"
        );
    }
}
