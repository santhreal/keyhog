//! Contract: `--format sarif` on a clean file exits 0 with SARIF object.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_sarif_clean_exit_zero() {
    let (_dir, path) = write_temp_file("clean.txt", "hello world\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "sarif",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let sarif: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("sarif json");
    assert!(sarif.get("runs").is_some());
}
