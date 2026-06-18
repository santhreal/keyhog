//! e2e: the GPU is NOT auto-selected without `KEYHOG_GPU_AUTOROUTE`
//! (TESTING vector 12, lane 9) — the MEASURED-FACT contract, end to end.
//!
//! MEASURED FACT (today, RTX 5090): the GPU megakernel is 1.7–6× SLOWER than
//! SIMD at every size for keyhog's detector set (catalog upload ~1 GB one-time,
//! per-rule-DFA kernel ~18 MiB/s, phase-2 on CPU regardless). So auto-routing
//! must NEVER pick the GPU on its own; the operator opts in with
//! `KEYHOG_GPU_AUTOROUTE=1`, and `--backend gpu` still forces it for
//! parity/research.
//!
//! The opt-in gate lives in a private CLI function
//! (`dispatch/backend.rs::measure_fastest_correct_backend`); the scanner-side
//! pure-fn inputs it consults are pinned in
//! `crates/scanner/tests/autoroute_gpu_optin_contract.rs`. THIS test pins the
//! operator-visible end: the `⚙ backend:` rationale line the real binary prints
//! to stderr.
//!
//! Why these assertions hold on EVERY host (deterministic, machine-independent):
//!   * WITHOUT persisted calibration, the auto path fails with
//!     "autoroute calibration required" rather than guessing a backend. If a
//!     valid cache is present, it still must not report GPU as selected unless
//!     calibration picked it.
//!   * `--backend gpu` reports it as FORCED (`forced via …`), not auto-selected
//!     when a usable adapter exists; on a host with no usable adapter it fails
//!     closed instead of silently substituting SIMD.
//!
//! The existing `progress_flag_emits_routing_decision_summary` test only covers
//! a single tiny file (always SIMD, never clears any GPU floor). This test uses
//! a multi-megabyte input that WOULD clear the high-tier 2 MiB GPU floor, so it
//! actually exercises the case the opt-in gate exists to veto.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A ~3 MiB clean file: past the high-tier 2 MiB GPU floor, so the routing
/// decision is non-trivial (a tiny file always trivially routes to SIMD). Clean
/// content so the scan exits 0 and the assertion is about routing, not findings.
fn large_clean_file() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("large_clean.txt");
    let mut f = std::fs::File::create(&path).expect("create large file");
    // ~3 MiB of prose-shaped lines with no credential-shaped tokens.
    let line = "the quick brown fox jumps over the lazy dog and writes some code\n";
    let target = 3 * 1024 * 1024;
    let mut written = 0usize;
    while written < target {
        f.write_all(line.as_bytes()).expect("write");
        written += line.len();
    }
    f.flush().expect("flush");
    (dir, path)
}

/// Run a scan and return (exit_code, stderr). `--progress` forces the routing
/// rationale line to be emitted on the completion summary.
fn scan(path: &PathBuf, env: &[(&str, &str)], extra: &[&str]) -> (Option<i32>, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--no-daemon", "--progress", "--format", "json"]);
    cmd.args(extra);
    cmd.arg(path);
    // Strip any ambient routing env so the test is hermetic, then apply ours.
    cmd.env_remove("KEYHOG_GPU_AUTOROUTE");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn without_optin_a_large_scan_never_reports_gpu_auto_selected() {
    let (_dir, path) = large_clean_file();
    let (code, stderr) = scan(&path, &[], &[]);

    if code == Some(0) {
        assert!(
            stderr.contains("⚙ backend:"),
            "scan must emit the routing rationale line; stderr={stderr}"
        );
        assert!(
            !stderr.contains("gpu-zero-copy (selected"),
            "the GPU must NOT be auto-selected without calibration evidence; stderr={stderr}"
        );
    } else {
        assert!(
            code == Some(2) && stderr.contains("autoroute calibration required"),
            "auto scan without a valid calibration record must fail loudly, not guess; \
             code={code:?} stderr={stderr}"
        );
    }
}

#[test]
fn forcing_backend_gpu_reports_a_forced_line_not_an_auto_selection() {
    let (_dir, path) = large_clean_file();
    // `--backend gpu` forces the device path. A GPU host completes and reports
    // the forced backend; a no-GPU host must fail closed rather than silently
    // substituting SIMD.
    let (code, stderr) = scan(&path, &[], &["--backend", "gpu"]);

    if code == Some(0) {
        assert!(
            stderr.contains("⚙ backend:"),
            "forced-GPU scan must emit the routing rationale line; stderr={stderr}"
        );
        assert!(
            stderr.contains("forced via --backend"),
            "an explicit --backend gpu must be reported as forced, not as an \
             auto-routing decision; stderr={stderr}"
        );
    } else {
        assert!(
            matches!(code, Some(2) | Some(12))
                && (stderr.contains("selected but GPU stack unavailable")
                    || stderr.contains("Required GPU unavailable")
                    || stderr.contains("KEYHOG_REQUIRE_GPU")),
            "--backend gpu without a usable GPU must fail closed with a visible \
             diagnostic; code={code:?} stderr={stderr}"
        );
    }
}

#[test]
fn optin_env_is_accepted_and_does_not_break_a_clean_scan() {
    // With the opt-in set, calibration is allowed to include GPU candidates, but
    // a normal production scan still must not benchmark or guess without a
    // persisted decision.
    let (_dir, path) = large_clean_file();
    let (code, stderr) = scan(&path, &[("KEYHOG_GPU_AUTOROUTE", "1")], &[]);

    assert!(
        code == Some(0) || (code == Some(2) && stderr.contains("autoroute calibration required")),
        "KEYHOG_GPU_AUTOROUTE=1 must either use valid persisted calibration or fail loudly; \
         code={code:?} stderr={stderr}"
    );
}
