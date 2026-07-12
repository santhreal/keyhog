//! E2E: diff of identical baselines exits 0.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;
use tempfile::TempDir;

#[test]
fn diff_identical_baselines_exit_zero() {
    let dir = TempDir::new().expect("tempdir");
    let (_fdir, fixture) = write_temp_file(
        "planted.txt",
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n",
    );
    let baseline = dir.path().join("baseline.json");
    let create = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--create-baseline",
        ])
        .arg(baseline.to_str().unwrap())
        .arg("--format")
        .arg("json")
        .arg(&fixture)
        .output()
        .expect("create baseline");
    assert_eq!(create.status.code(), Some(0));
    let output = Command::new(binary())
        .args(["diff"])
        .arg(&baseline)
        .arg(&baseline)
        .output()
        .expect("diff");
    assert_eq!(
        output.status.code(),
        Some(0),
        "identical baselines must exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
