//! E2E: `calibrate --show` prints calibration header.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn calibrate_show_header() {
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
        stdout.contains("calibration"),
        "calibrate --show must print header; got: {stdout}"
    );
}
