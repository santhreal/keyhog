//! R5-D2 / KH-GAP-174: when GPU self-test passes, `--require-gpu` scan must exit 0.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn require_gpu_scan_when_self_test_passes() {
    let self_test = Command::new(binary())
        .args(["backend", "--self-test"])
        .output()
        .expect("backend self-test spawn");
    // `backend --self-test` exits 0 both when the GPU stack PASSES and when it
    // SKIPS (no adapter, or a build without the `gpu` feature — e.g. ci-lean).
    // This test only has a contract when a GPU genuinely PASSED, so skip unless
    // the self-test ran a real GPU: a SKIP / "no GPU adapter" result means
    // `--require-gpu` is *correctly* allowed to refuse, and asserting exit 0
    // here would be a host/build-dependent false failure (Law 8: no usable GPU
    // is honest, not a bug to paper over).
    let self_test_report = format!(
        "{}{}",
        String::from_utf8_lossy(&self_test.stdout),
        String::from_utf8_lossy(&self_test.stderr)
    );
    let gpu_unavailable = self_test_report.contains("no GPU adapter")
        || self_test_report.contains("SKIP")
        || self_test_report.contains("not detected");
    if self_test.status.code() != Some(0) || gpu_unavailable {
        eprintln!("skip: GPU self-test did not PASS a real GPU on this host; report={self_test_report}");
        return;
    }

    let (_dir, path) = write_temp_file("clean.txt", "hello\n");
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
        .arg(&path)
        .output()
        .expect("spawn");

    assert_eq!(
        output.status.code(),
        Some(0),
        "--require-gpu must succeed when GPU stack healthy; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("falling back to CPU"),
        "must not silently CPU-fallback under --require-gpu; stderr={stderr}"
    );
}
