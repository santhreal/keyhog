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
match_confidence = { literal_prefix_weight = 0.35, context_anchor_weight = 0.20, entropy_weight = 0.20, high_entropy_partial_weight = 0.12, moderate_entropy_threshold = 3.0, moderate_entropy_weight = 0.05, low_entropy_penalty_floor = 2.0, low_entropy_min_match_length = 10, low_entropy_penalty_multiplier = 0.60, keyword_nearby_weight = 0.10, sensitive_file_weight = 0.10, companion_weight = 0.05, very_high_entropy_margin = 1.3, named_anchor_floor = 0.55, assignment_context_multiplier = 1.0, string_literal_context_multiplier = 0.9, unknown_context_multiplier = 0.8, documentation_context_multiplier = 0.3, comment_context_multiplier = 0.4, test_context_multiplier = 0.3, encrypted_context_multiplier = 0.05, soft_context_suppression_threshold = 0.5, encrypted_context_suppression_threshold = 0.8, post_match = { placeholder_multiplier = 0.05, minimum_byte_diversity = 0.1, low_diversity_multiplier = 0.1, maximum_repeat_ratio = 0.8, degenerate_run_min_length = 10, degenerate_repeat_multiplier = 0.1, fixture_path_multiplier = 0.5, ml_context_reapply_below = 0.95 } }
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
