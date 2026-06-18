//! Regression: `KEYHOG_REQUIRE_GPU=1` must FAIL CLOSED (exit 12) on the
//! no-GPU path, independent of backend routing (findings C0 / C1).
//!
//! Before the fix the require-GPU hard-fail only lived inside the
//! GPU-SELECTED dispatch paths. On a host with no discrete GPU, routing
//! degraded to SimdCpu, those paths were never reached, and the scan
//! completed on CPU exiting 0/1/10 instead of the documented exit 12 - the
//! literal `require-gpu-fails-closed|KEYHOG_REQUIRE_GPU=1|...|12` docker
//! scenario (tests/docker/scenarios.sh) and the env.md contract
//! ("refuse to run when no usable GPU adapter is detected").
//!
//! The CLI now runs an explicit require-GPU preflight before any scan
//! (`keyhog_scanner::gpu::require_gpu_preflight`, wired in
//! `orchestrator::run`) that returns the documented `ExitCode` 12 through
//! the CLI - not a scanner-lib `process::exit` - so an embedder using the
//! library directly is never hard-killed (finding M12).

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// Write a planted AWS credential to a temp file and return (dir, path).
/// The dir guard must stay alive for the scan to see the file.
fn aws_leak_fixture() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("aws_leak.env");
    // Split literal so this source file is not itself a self-flagging leak.
    let fixture = concat!("AWS_ACCESS_KEY_ID = \"AKIA", "QYLPMN5HFIQR7XYA\"\n");
    std::fs::write(&path, fixture).expect("write fixture");
    (dir, path)
}

/// Deterministic, host-independent core of the contract: when the operator
/// both REQUIRES a GPU and forbids GPU init (`KEYHOG_NO_GPU=1`), no usable
/// GPU can possibly be present, so the preflight must fail closed with the
/// documented exit code 12 - on any host, GPU box or not. This pins the
/// fail-closed behavior without depending on the CI runner lacking a GPU.
#[test]
fn require_gpu_with_no_gpu_forced_exits_twelve() {
    let (_dir, path) = aws_leak_fixture();

    let output = Command::new(binary())
        .arg("scan")
        .arg(&path)
        .env("KEYHOG_REQUIRE_GPU", "1")
        .env("KEYHOG_NO_GPU", "1")
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(12),
        "KEYHOG_REQUIRE_GPU=1 with no usable GPU must exit 12 (fail closed), \
         not silently scan on CPU; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("KEYHOG_REQUIRE_GPU"),
        "exit-12 diagnostic should name KEYHOG_REQUIRE_GPU; stderr={stderr}"
    );
}

/// Detect whether this host reports a usable (non-software) GPU by reading
/// the `keyhog backend` hardware report. Used to gate the natural docker
/// scenario below so it asserts the strict contract only on the no-GPU
/// hosts (CI runners, the docker test image) the flag targets.
fn host_has_usable_gpu() -> bool {
    let out = Command::new(binary())
        .arg("backend")
        .output()
        .expect("spawn keyhog backend");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let gpu_line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with("gpu:"))
        .unwrap_or("");
    !gpu_line.contains("not detected") && !gpu_line.contains("software renderer")
}

/// The literal docker scenario: `KEYHOG_REQUIRE_GPU=1 keyhog scan <leak>`
/// with nothing else set. On a no-GPU host (CI runners always set
/// CI=true/GITHUB_ACTIONS=true, which previously auto-skipped the GPU and
/// masked the requirement - finding C1) this must still exit 12. The
/// require flag now forces `env_no_gpu()` to return false so the CI
/// auto-skip cannot defeat the gate. On a real GPU host the scan proceeds
/// normally, so we only assert the strict exit 12 when no usable GPU is
/// detected.
#[test]
fn require_gpu_on_no_gpu_host_exits_twelve() {
    if host_has_usable_gpu() {
        // Real GPU present: the requirement is satisfiable, so the scan
        // runs and exits on the finding (1) rather than the require gate.
        // The fail-closed contract is exercised deterministically by
        // `require_gpu_with_no_gpu_forced_exits_twelve` regardless.
        return;
    }

    let (_dir, path) = aws_leak_fixture();

    let output = Command::new(binary())
        .arg("scan")
        .arg(&path)
        .env("KEYHOG_REQUIRE_GPU", "1")
        .env_remove("KEYHOG_NO_GPU")
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(12),
        "on a no-GPU host KEYHOG_REQUIRE_GPU=1 must fail closed with exit 12 \
         (the CI auto-skip must not mask the requirement); stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
