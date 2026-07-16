//! E2E: `detectors --fix` must write valid rewrites and fail unsafe ones.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn detectors_fix_valid_rewrite_writes_file() {
    let dir = TempDir::new().expect("tempdir");
    let detector = dir.path().join("valid.toml");
    let original = r#"
[detector]
id = "fix-template"
name = "Fix Template"
service = "example"
severity = "low"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["EXAMPLE"]

[[detector.patterns]]
regex = "EXAMPLE_[A-Z0-9]{8}"

[detector.verify]
method = "GET"
url = "https://api.example.com/{tenant}/token"
"#;
    std::fs::write(&detector, original).expect("write valid detector");

    let output = Command::new(binary())
        .args(["detectors", "--fix", "--detectors"])
        .arg(dir.path())
        .output()
        .expect("spawn keyhog detectors --fix");

    assert_eq!(
        output.status.code(),
        Some(0),
        "`detectors --fix` must rewrite valid detector TOML; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rewritten = std::fs::read_to_string(&detector).expect("read rewritten detector");
    assert!(
        rewritten.contains("https://api.example.com/{{tenant}}/token"),
        "valid detector URL must be rewritten; got:\n{rewritten}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("fixed") && stdout.contains("1 rewrite"),
        "stdout must report the mutation; stdout={stdout}"
    );
}

#[test]
fn detectors_fix_invalid_rewrite_blocks_without_writing() {
    let dir = TempDir::new().expect("tempdir");
    let valid_detector = dir.path().join("valid.toml");
    let valid_original = r#"
[detector]
id = "fix-template"
name = "Fix Template"
service = "example"
severity = "low"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["EXAMPLE"]

[[detector.patterns]]
regex = "EXAMPLE_[A-Z0-9]{8}"

[detector.verify]
method = "GET"
url = "https://api.example.com/{tenant}/token"
"#;
    std::fs::write(&valid_detector, valid_original).expect("write valid detector");

    let broken_detector = dir.path().join("broken.toml");
    let broken_original = r#"
[detector.verify]
url = "https://api.example.com/{tenant}/token"
"#;
    std::fs::write(&broken_detector, broken_original).expect("write broken detector");

    let output = Command::new(binary())
        .args(["detectors", "--fix", "--detectors"])
        .arg(dir.path())
        .output()
        .expect("spawn keyhog detectors --fix");

    assert_eq!(
        output.status.code(),
        Some(2),
        "`detectors --fix` must fail when a rewrite candidate cannot be validated; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&broken_detector).expect("read broken detector"),
        broken_original,
        "failed detector rewrite must not be written"
    );
    assert_eq!(
        std::fs::read_to_string(&valid_detector).expect("read valid detector"),
        valid_original,
        "valid rewrite candidates must not be partially written when another detector blocks --fix"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("could not safely rewrite") && stderr.contains("no files were written"),
        "stderr must make the failed mutation explicit; stderr={stderr}"
    );
    assert!(
        stderr.contains("broken.toml"),
        "stderr must name the detector file that blocked the rewrite; stderr={stderr}"
    );
}

#[test]
fn detectors_fix_oversized_detector_fails_before_rewrite() {
    let dir = TempDir::new().expect("tempdir");
    let oversized = dir.path().join("oversized.toml");
    let file = std::fs::File::create(&oversized).expect("create oversized detector");
    file.set_len(keyhog_core::DETECTOR_TOML_FILE_BYTES + 1)
        .expect("make oversized sparse detector");

    let output = Command::new(binary())
        .args(["detectors", "--fix", "--detectors"])
        .arg(dir.path())
        .output()
        .expect("spawn keyhog detectors --fix");

    assert_eq!(
        output.status.code(),
        Some(2),
        "`detectors --fix` must fail on oversized detector TOML; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("oversized.toml") && stderr.contains("exceeds"),
        "stderr must name the oversized detector and the cap failure; stderr={stderr}"
    );
}
