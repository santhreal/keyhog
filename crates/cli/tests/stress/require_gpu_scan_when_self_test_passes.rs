//! R5-D2 / KH-GAP-174: when GPU self-test passes, `--require-gpu` scan must exit 0.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn require_gpu_scan_when_self_test_passes() {
    let self_test = Command::new(binary())
        .args(["backend", "--self-test"])
        .output()
        .expect("backend self-test spawn");
    if self_test.status.code() != Some(0) {
        eprintln!(
            "skip: GPU self-test failed on this host; stderr={}",
            String::from_utf8_lossy(&self_test.stderr)
        );
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
