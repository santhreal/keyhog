//! Regression: an explicit detector directory with one malformed TOML must not
//! scan with a silently smaller detector corpus.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

fn valid_detector_toml() -> &'static str {
    r#"
[detector]
id = "demo-token"
name = "Demo Token"
service = "demo"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["DEMO"]

[[detector.patterns]]
regex = "DEMO_[A-Z0-9]{8}"
"#
}

#[test]
fn scan_rejects_partial_detector_corpus() {
    let dir = TempDir::new().expect("tempdir");
    let detectors = dir.path().join("detectors");
    let target = dir.path().join("target");
    std::fs::create_dir_all(&detectors).expect("mkdir detectors");
    std::fs::create_dir_all(&target).expect("mkdir target");
    std::fs::write(detectors.join("valid.toml"), valid_detector_toml()).expect("write valid");
    std::fs::write(detectors.join("broken.toml"), "[detector").expect("write broken");
    std::fs::write(target.join("input.txt"), "DEMO_ABCDEFGH\n").expect("write scan target");

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "cpu",
            "--daemon=off",
            "--format",
            "json",
            "--detectors",
        ])
        .arg(&detectors)
        .arg(&target)
        .env("NO_COLOR", "1")
        .output()
        .expect("spawn keyhog scan");

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "partial detector corpus must be a user-error exit; got {combined}"
    );
    assert!(
        combined.contains("partial detector corpus")
            && combined.contains("broken.toml")
            && combined.contains("Fix: repair the named TOML"),
        "scan failure must name the malformed detector and fix; got {combined}"
    );
    assert!(
        output.stdout.is_empty(),
        "corpus rejection must happen before partial scan output; stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
}
