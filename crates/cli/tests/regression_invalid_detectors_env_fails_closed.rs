use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn workspace_detectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../detectors")
        .canonicalize()
        .expect("workspace detectors dir")
}

#[test]
fn invalid_keyhog_detectors_env_exits_two_instead_of_embedded_fallback() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    let missing = dir.path().join("missing-detectors");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");

    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--backend", "cpu", "--format", "json"])
        .arg(&target)
        .env("KEYHOG_DETECTORS", &missing)
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "bad KEYHOG_DETECTORS must not silently fall back to embedded/default detectors; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("KEYHOG_DETECTORS points at")
            && stderr.contains("missing-detectors")
            && stderr.contains("Fix: unset KEYHOG_DETECTORS"),
        "diagnostic must name the bad detector env and the fix; stderr={stderr}"
    );
}

#[test]
fn explicit_detectors_path_overrides_invalid_keyhog_detectors_env() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    let missing = dir.path().join("missing-detectors");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");
    let detectors = workspace_detectors();

    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--backend", "cpu", "--format", "json", "--detectors"])
        .arg(&detectors)
        .arg(&target)
        .env("KEYHOG_DETECTORS", &missing)
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(0),
        "explicit --detectors must win over KEYHOG_DETECTORS; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
