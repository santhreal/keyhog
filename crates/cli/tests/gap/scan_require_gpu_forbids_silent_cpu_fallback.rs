//! R3-D / KH-GAP-041 + KH-GAP-093: when GPU self-test fails, forced GPU scan
//! with KEYHOG_REQUIRE_GPU=1 must not exit 0 after silent CPU fallback.

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
        .env("KEYHOG_REQUIRE_GPU", "1")
        .args([
            "scan",
            "--no-daemon",
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
        "KEYHOG_REQUIRE_GPU=1 + --backend gpu must not exit 0 when GPU self-test failed; stderr={stderr}"
    );
    assert!(
        stderr.contains("falling back to CPU") || code == 11,
        "expected GPU dispatch failure signal (panic exit 11 or fallback log); exit={code} stderr={stderr}"
    );
}
