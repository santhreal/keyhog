//! e2e: the GPU is NOT auto-selected without `--autoroute-gpu`
//! (TESTING vector 12, lane 9) — the MEASURED-FACT contract, end to end.
//!
//! MEASURED FACT (2026-06-19, RTX 5090): the live region-presence GPU route
//! still did not beat best CPU/SIMD through 64 MiB, including the required
//! 8 MiB cell. So auto-routing must never pick GPU from a fixed heuristic; it
//! must consume install-time calibration evidence. The operator opts GPU into
//! calibration with `--autoroute-gpu`, and `--backend gpu` still forces it for
//! parity/research.
//!
//! The calibration owner is pinned in `crates/cli/tests/unit/orchestrator/`.
//! Scanner-side heuristic predicate values are pinned in
//! `crates/scanner/tests/autoroute_gpu_optin_contract.rs`. THIS test pins the
//! operator-visible end: the `INFO backend:` rationale line the real binary
//! prints to stderr.
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
//! a multi-megabyte input in the formerly over-eager GPU range, so it exercises
//! the cache-required auto-routing contract without making the test huge.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A ~3 MiB clean file: large enough to catch the retired over-eager GPU floor
/// while still cheap in e2e. Clean content so the scan exits 0 and the
/// assertion is about routing, not findings.
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
fn scan(path: &PathBuf, extra: &[&str]) -> (Option<i32>, String) {
    let mut cmd = Command::new(binary());
    cmd.args(["scan", "--daemon=off", "--progress", "--format", "json"]);
    cmd.args(extra);
    cmd.arg(path);
    let output = cmd.output().expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn without_optin_a_large_scan_never_reports_gpu_auto_selected() {
    let (_dir, path) = large_clean_file();
    let (code, stderr) = scan(&path, &[]);

    if code == Some(0) {
        assert!(
            stderr.contains("INFO backend:"),
            "scan must emit the routing rationale line; stderr={stderr}"
        );
        assert!(
            !stderr.contains("gpu-region-presence (selected"),
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
    let (code, stderr) = scan(&path, &["--backend", "gpu"]);

    if code == Some(0) {
        assert!(
            stderr.contains("INFO backend:"),
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
                    || stderr.contains("--require-gpu")),
            "--backend gpu without a usable GPU must fail closed with a visible \
             diagnostic; code={code:?} stderr={stderr}"
        );
    }
}

#[test]
fn autoroute_gpu_flag_is_accepted_and_does_not_break_a_clean_scan() {
    // With the opt-in set, calibration is allowed to include GPU candidates, but
    // a normal production scan still must not benchmark or guess without a
    // persisted decision.
    let (_dir, path) = large_clean_file();
    let (code, stderr) = scan(&path, &["--autoroute-gpu"]);

    assert!(
        code == Some(0) || (code == Some(2) && stderr.contains("autoroute calibration required")),
        "--autoroute-gpu must either use valid persisted calibration or fail loudly; \
         code={code:?} stderr={stderr}"
    );
}
