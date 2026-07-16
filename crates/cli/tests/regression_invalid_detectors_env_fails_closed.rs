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
    let mut cases: Vec<&[&str]> = vec![
        &["detectors", "--detectors", "detectors"],
        &["explain", "aws-access-key", "--detectors", "detectors"],
        &["watch", "--detectors", "detectors"],
        &["scan-system", "--detectors", "detectors"],
    ];
    #[cfg(unix)]
    cases.push(&[
        "daemon",
        "start",
        "--backend",
        "cpu",
        "--detectors",
        "detectors",
    ]);

    for args in cases {
        let output = Command::new(binary())
            .current_dir(dir.path())
            .args(args)
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

#[test]
fn list_and_explain_discover_the_installed_detector_corpus() {
    let home = TempDir::new().expect("home tempdir");
    let work = TempDir::new().expect("work tempdir");
    let detectors = home.path().join(".keyhog/detectors");
    std::fs::create_dir_all(&detectors).expect("create installed detector directory");
    std::fs::write(
        detectors.join("installed-discovery.toml"),
        r#"[detector]
id = "installed-discovery"
name = "Installed Discovery"
service = "test"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["INSTALLED_DISCOVERY"]

[[detector.patterns]]
regex = "INSTALLED_DISCOVERY_(?P<secret>[A-Z0-9]{20})"
description = "installed discovery fixture"
group = 1
"#,
    )
    .expect("write detector");

    for args in [
        vec!["detectors", "--format", "json"],
        vec!["explain", "installed-discovery"],
    ] {
        let output = Command::new(binary())
            .current_dir(work.path())
            .env("HOME", home.path())
            .env("XDG_DATA_HOME", home.path().join("xdg-data"))
            .env("XDG_DATA_DIRS", home.path().join("xdg-data-dirs"))
            .args(&args)
            .output()
            .unwrap_or_else(|error| panic!("spawn keyhog {args:?}: {error}"));
        assert_eq!(
            output.status.code(),
            Some(0),
            "installed detector discovery must succeed for {args:?}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("installed-discovery"),
            "installed detector must be visible for {args:?}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}
