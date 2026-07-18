//! E2E: invalid autoroute state completes through visible scalar recovery.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn scan_autoroute_missing_calibration_recovers_complete_input() {
    let dir = TempDir::new().expect("tempdir");
    let fixture = dir.path().join("clean.rs");
    std::fs::write(&fixture, "fn main() {}\n").expect("write fixture");
    let missing_cache = dir.path().join("missing-autoroute-cache.json");

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
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
        Some(0),
        "a clean scan must complete through visible scalar recovery; stderr={stderr}"
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "[]");
    assert!(
        stderr.contains("autoroute calibration required")
            && stderr.contains("No autoroute cache file exists")
            && stderr.contains("scalar correctness recovery")
            && stderr.contains("scan coverage is complete")
            && stderr.contains("keyhog calibrate-autoroute"),
        "stderr must identify invalid autoroute state, exact recovery, and repair; stderr={stderr}"
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
            "--daemon=off",
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

#[test]
fn scan_autoroute_zero_byte_file_does_not_require_cache_bucket() {
    for extra_args in [Vec::<&str>::new(), vec!["--batch-pipeline"]] {
        let dir = TempDir::new().expect("tempdir");
        let fixture = dir.path().join("empty.txt");
        std::fs::write(&fixture, "").expect("write empty fixture");
        let missing_cache = dir.path().join("missing-autoroute-cache.json");

        let mut command = Command::new(binary());
        command.args([
            "scan",
            "--daemon=off",
            "--no-config",
            "--format",
            "json",
            "--backend",
            "auto",
        ]);
        command.args(&extra_args);
        command
            .arg("--autoroute-cache")
            .arg(&missing_cache)
            .arg(&fixture);
        let output = command
            .env_remove("KEYHOG_BACKEND")
            .output()
            .expect("spawn keyhog scan");

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            output.status.code(),
            Some(0),
            "zero-byte autoroute scan must not require an impossible cache bucket; args={extra_args:?}; stderr={stderr}"
        );
        assert_eq!(
            stdout.trim(),
            "[]",
            "zero-byte autoroute scan must emit an empty finding set; args={extra_args:?}"
        );
        assert!(
            !stderr.contains("autoroute calibration required"),
            "zero-byte no-op batch must not query autoroute cache; args={extra_args:?}; stderr={stderr}"
        );
    }
}
