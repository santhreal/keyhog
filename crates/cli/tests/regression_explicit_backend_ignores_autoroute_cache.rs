use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn explicit_backend_does_not_load_stale_autoroute_cache() {
    let dir = TempDir::new().expect("tempdir");
    let fixture = dir.path().join("clean.rs");
    let cache = dir.path().join("autoroute.json");
    std::fs::write(&fixture, "fn main() {}\n").expect("write fixture");
    std::fs::write(&cache, br#"{"version":16,"decisions":[{}]}"#).expect("write stale cache");

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--no-config",
            "--format",
            "json",
            "--backend",
            "cpu",
        ])
        .arg("--autoroute-cache")
        .arg(&cache)
        .arg(&fixture)
        .env_remove("KEYHOG_BACKEND")
        .env_remove("KEYHOG_AUTOROUTE_CALIBRATE")
        .output()
        .expect("spawn keyhog scan");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "explicit CPU backend should scan clean input successfully; stderr={stderr}"
    );
    assert!(
        !stderr.contains("autoroute cache ignored")
            && !stderr.contains("autoroute calibration required"),
        "explicit backend routes must not parse or warn on autoroute cache state; stderr={stderr}"
    );
    let findings: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).expect("stdout is JSON findings");
    assert!(
        findings.is_empty(),
        "clean fixture should stay clean: {findings:?}"
    );
}
