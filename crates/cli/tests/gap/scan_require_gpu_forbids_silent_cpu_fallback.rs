//! R3-D / KH-GAP-041 + KH-GAP-093: when GPU self-test fails, forced GPU scan
//! with `--require-gpu` must not exit 0 after silent CPU fallback.

use crate::e2e::support::{binary, workspace_detectors};
use std::process::Command;

#[test]
fn scan_require_gpu_forbids_silent_cpu_fallback_on_gpu_backend() {
    let self_test = Command::new(binary())
        .args(["backend", "--self-test"])
        .output()
        .expect("backend self-test spawn");
    let gpu_broken = self_test.status.code() == Some(4);
    if !gpu_broken {
        // vyre_literal_set healthy — GPU path should succeed on clean corpus.
        return;
    }

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--require-gpu",
            "--backend",
            "gpu",
            "--format",
            "json",
        ])
        .arg(workspace_detectors())
        .output()
        .expect("spawn");

    let code = output.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_ne!(
        code, 0,
        "--require-gpu + --backend gpu must not exit 0 when GPU self-test failed; stderr={stderr}"
    );
    assert_eq!(
        code, 12,
        "--require-gpu must fail closed with the required-GPU exit code, not a scanner panic or CPU scan; stderr={stderr}"
    );
    assert!(
        stderr.contains("--require-gpu") || stderr.to_lowercase().contains("gpu"),
        "required-GPU failure must be operator-visible; exit={code} stderr={stderr}"
    );
    assert!(
        !stderr.contains("falling back to CPU"),
        "--require-gpu must never present CPU fallback as an acceptable route; stderr={stderr}"
    );
}
