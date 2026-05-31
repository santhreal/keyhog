//! Adversarial: scan --baseline with missing file must exit 2.

use crate::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_baseline_missing_file_rejects_hostile_path() {
    let (_dir, path) = write_temp_file("clean.txt", "hello\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--format",
            "json",
            "--baseline",
            "/nonexistent/keyhog-adversarial-baseline.json",
        ])
        .arg(&path)
        .output()
        .expect("spawn scan --baseline");
    assert_eq!(
        output.status.code(),
        Some(2),
        "missing baseline must exit 2; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("baseline") || stderr.contains("Baseline"),
        "stderr must mention baseline; got: {stderr}"
    );
}
