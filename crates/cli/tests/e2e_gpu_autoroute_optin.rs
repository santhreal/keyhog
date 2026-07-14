//! E2E: calibration controls never turn a normal scan into an implicit probe.
//!
//! The production crossover benchmark separately proves the warm RTX 5090 GPU
//! route beats Hyperscan at 8 MiB. This test does not infer that winner from a
//! threshold: auto-routing consumes persisted local calibration evidence.
//! Canonical maintenance calibration enables every eligible GPU peer, while
//! low-level direct calibration uses `--autoroute-gpu`. Exact GPU backends remain
//! an explicit parity/research route.
//!
//! The calibration owner is pinned in `crates/cli/tests/unit/orchestrator/`.
//! Scanner-side heuristic predicate values are pinned in
//! `crates/scanner/tests/autoroute_gpu_optin_contract.rs`. THIS test pins the
//! operator-visible end: the `INFO backend:` rationale line the real binary
//! prints to stderr.
//!
//! Why these assertions hold on EVERY host (deterministic, machine-independent):
//!   * Without persisted calibration, the auto path fails with
//!     "autoroute calibration required" rather than guessing a backend. If a
//!     valid cache is present, normal scans may select GPU only when calibration
//!     picked it; they do not repeat the calibration admission flag.
//!   * an exact GPU backend reports it as FORCED (`forced via …`), not auto-selected
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
    cmd.env(
        "XDG_CACHE_HOME",
        path.parent().expect("fixture path has parent"),
    );
    let output = cmd.output().expect("spawn keyhog scan");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn without_persisted_evidence_a_large_auto_scan_fails_closed() {
    let (_dir, path) = large_clean_file();
    let (code, stderr) = scan(&path, &[]);

    assert!(
        code == Some(2) && stderr.contains("autoroute calibration required"),
        "auto scan without a valid calibration record must fail loudly, not guess; \
         code={code:?} stderr={stderr}"
    );
}

#[test]
fn forcing_backend_gpu_reports_a_forced_line_not_an_auto_selection() {
    let (_dir, path) = large_clean_file();
    // `--backend gpu-wgpu` forces one device path. A GPU host completes and reports
    // the forced backend; a no-GPU host must fail closed rather than silently
    // substituting SIMD.
    let (code, stderr) = scan(&path, &["--backend", "gpu-wgpu"]);

    if code == Some(0) {
        assert!(
            stderr.contains("INFO backend:"),
            "forced-GPU scan must emit the routing rationale line; stderr={stderr}"
        );
        assert!(
            stderr.contains("forced via --backend"),
            "an explicit --backend gpu-wgpu must be reported as forced, not as an \
             auto-routing decision; stderr={stderr}"
        );
    } else {
        assert!(
            matches!(code, Some(2) | Some(12))
                && (stderr.contains("selected but GPU stack unavailable")
                    || stderr.contains("Selected GPU unavailable")
                    || stderr.contains("--require-gpu")),
            "--backend gpu-wgpu without a usable GPU must fail closed with a visible \
             diagnostic; code={code:?} stderr={stderr}"
        );
    }
}

#[test]
fn autoroute_gpu_admission_flag_does_not_make_a_normal_scan_calibrate() {
    // Candidate admission is meaningful only with explicit calibration mode.
    // A normal scan still refuses to benchmark or guess without persisted proof.
    let (_dir, path) = large_clean_file();
    let (code, stderr) = scan(&path, &["--autoroute-gpu"]);

    assert!(
        code == Some(2) && stderr.contains("autoroute calibration required"),
        "--autoroute-gpu alone must not turn a normal scan into calibration; \
         code={code:?} stderr={stderr}"
    );
}
