//! Adversarial: calibrate --show with missing cache prints header and exits 0.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn calibrate_show_missing_cache_file_exits_zero() {
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("missing-calibration.json");
    let output = Command::new(binary())
        .args(["calibrate", "--show", "--cache"])
        .arg(&cache)
        .output()
        .expect("spawn calibrate --show");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("detector") || stdout.contains("calibr") || stdout.contains("TP"),
        "calibrate --show must print counters header even without cache; got: {stdout}"
    );
}
