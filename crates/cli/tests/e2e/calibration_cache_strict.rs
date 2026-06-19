//! E2E: explicit scan calibration caches must fail closed when damaged.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn scan_explicit_corrupt_calibration_cache_exits_two_before_scanning() {
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("calibration.json");
    std::fs::write(&cache, "not-json").expect("write corrupt cache");

    let output = Command::new(binary())
        .args([
            "scan",
            "--stdin",
            "--backend",
            "simd",
            "--calibration-cache",
        ])
        .arg(&cache)
        .output()
        .expect("spawn keyhog scan with corrupt calibration cache");

    assert_eq!(
        output.status.code(),
        Some(2),
        "corrupt explicit calibration cache must fail closed; stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not valid JSON")
            && stderr.contains("--calibration-cache")
            && stderr.contains("hermetic scan"),
        "stderr must name the corrupt cache and repair path; stderr={stderr}"
    );
}

#[test]
fn scan_missing_explicit_calibration_cache_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let cache = dir.path().join("missing-calibration.json");

    let output = Command::new(binary())
        .args([
            "scan",
            "--stdin",
            "--backend",
            "simd",
            "--calibration-cache",
        ])
        .arg(&cache)
        .output()
        .expect("spawn keyhog scan with missing calibration cache");

    assert_eq!(
        output.status.code(),
        Some(2),
        "missing explicit calibration cache must fail closed; stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("does not exist")
            && stderr.contains("keyhog calibrate --cache")
            && stderr.contains("hermetic scan"),
        "stderr must name the missing cache and repair path; stderr={stderr}"
    );
}
