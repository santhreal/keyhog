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
fn legacy_keyhog_detectors_env_is_ignored() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    let missing = dir.path().join("missing-detectors");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
        ])
        .arg(&target)
        .env("KEYHOG_DETECTORS", &missing)
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(0),
        "legacy KEYHOG_DETECTORS must not control detector loading; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("KEYHOG_DETECTORS"),
        "legacy detector env must not affect operator-visible behavior; stderr={stderr}"
    );
}

#[test]
fn explicit_detectors_path_works_with_legacy_keyhog_detectors_env_present() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    let missing = dir.path().join("missing-detectors");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");
    let detectors = workspace_detectors();

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--format",
            "json",
            "--detectors",
        ])
        .arg(&detectors)
        .arg(&target)
        .env("KEYHOG_DETECTORS", &missing)
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(0),
        "explicit --detectors must work even when legacy KEYHOG_DETECTORS is present; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn explicitly_selected_default_spelling_does_not_fall_back_to_embedded_detectors() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("clean.txt");
    std::fs::write(&target, "clean fixture\n").expect("write clean fixture");

    let output = Command::new(binary())
        .current_dir(dir.path())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "cpu",
            "--detectors",
            "detectors",
        ])
        .arg(&target)
        .output()
        .expect("spawn keyhog scan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "an explicitly named missing corpus must be a user error; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("explicit detectors directory 'detectors' does not exist")
            && stderr.contains("omit --detectors"),
        "error must distinguish an explicit missing corpus from the omitted default; stderr={stderr}"
    );
}

#[test]
fn every_detector_consuming_command_rejects_an_explicit_missing_default_spelling() {
    let dir = TempDir::new().expect("tempdir");
    let cases: &[&[&str]] = &[
        &["detectors", "--detectors", "detectors"],
        &["explain", "aws-access-key", "--detectors", "detectors"],
        &["watch", "--detectors", "detectors"],
        &["scan-system", "--detectors", "detectors"],
        &[
            "daemon",
            "start",
            "--backend",
            "cpu",
            "--detectors",
            "detectors",
        ],
    ];

    for args in cases {
        let output = Command::new(binary())
            .current_dir(dir.path())
            .args(*args)
            .output()
            .unwrap_or_else(|error| panic!("spawn keyhog {args:?}: {error}"));
        assert_eq!(
            output.status.code(),
            Some(2),
            "explicit missing detector corpus must fail for {args:?}; stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("explicit detectors directory 'detectors' does not exist")
                && stderr.contains("omit --detectors"),
            "error must preserve detector-path provenance for {args:?}; stderr={stderr}"
        );
    }
}
