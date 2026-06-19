//! E2E: `--backend auto` fails loud when no autoroute calibration covers the workload.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn scan_autoroute_missing_calibration_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let fixture = dir.path().join("clean.rs");
    std::fs::write(&fixture, "fn main() {}\n").expect("write fixture");
    let missing_cache = dir.path().join("missing-autoroute-cache.json");

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--no-config",
            "--format",
            "json",
            "--backend",
            "auto",
        ])
        .arg("--autoroute-cache")
        .arg(&missing_cache)
        .arg(&fixture)
        .env_remove("KEYHOG_BACKEND")
        .output()
        .expect("spawn keyhog scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "missing autoroute calibration must be a config/user error; stderr={stderr}"
    );
    assert!(
        stderr.contains("autoroute calibration required")
            && stderr.contains("No autoroute cache file exists")
            && stderr.contains("install.sh --calibrate")
            && stderr.contains("install.ps1 -Calibrate"),
        "stderr must explain the missing autoroute calibration and fix; stderr={stderr}"
    );
}

#[test]
fn scan_autoroute_relative_cache_path_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let fixture = dir.path().join("clean.rs");
    std::fs::write(&fixture, "fn main() {}\n").expect("write fixture");

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--no-config",
            "--format",
            "json",
            "--backend",
            "auto",
        ])
        .args(["--autoroute-cache", "relative-autoroute-cache.json"])
        .arg(&fixture)
        .env_remove("KEYHOG_BACKEND")
        .output()
        .expect("spawn keyhog scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "relative autoroute cache path must be a config/user error; stderr={stderr}"
    );
    assert!(
        stderr.contains("autoroute cache path must be an absolute file path")
            && stderr.contains("relative-autoroute-cache.json"),
        "stderr must surface the bad cache path and fix; stderr={stderr}"
    );
}
