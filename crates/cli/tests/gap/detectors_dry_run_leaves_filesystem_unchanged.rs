//! KH-184: `keyhog detectors --fix --dry-run` must preview rewrites without changing files.
//!
//! Acceptance: Running with `--dry-run` shows compiled delta, reports files that
//! would change, and leaves the filesystem state unchanged. Running without
//! `--dry-run` applies the changes. Invalid detector TOMLs trigger error exit.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn test_detectors_dry_run_and_fix() {
    let dir = tempdir().expect("failed to create temp dir");
    let temp_path = dir.path();

    let valid_toml_content = r#"[detector]
id = "valid-detector"
name = "Valid Detector"
service = "valid"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
keywords = ["VALID"]

[[detector.patterns]]
regex = "VALID-(?P<secret>[a-zA-Z0-9_-]{20,})"
description = "Valid pattern"
group = 1

[detector.verify]
url = "https://api.valid.com/v1/{secret}"
allowed_domains = ["api.valid.com"]
"#;

    let valid_path = temp_path.join("valid-detector.toml");
    fs::write(&valid_path, valid_toml_content).expect("failed to write valid detector TOML");

    // 1. Dry run on valid detector
    let output = Command::new(binary())
        .args([
            "detectors",
            "--detectors",
            temp_path.to_str().unwrap(),
            "--fix",
            "--dry-run",
        ])
        .output()
        .expect("failed to run keyhog detectors --fix --dry-run");

    assert!(
        output.status.success(),
        "dry-run on valid detector must succeed"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("would fix"),
        "stdout must mention what would be fixed, got: {stdout}"
    );
    assert!(
        stdout
            .contains("Dry-run complete: 1 file(s) inspected, 1 would change, 1 total rewrite(s)."),
        "stdout must show expected dry-run complete summary, got: {stdout}"
    );

    // Verify file content is unchanged
    let content_after_dry_run =
        fs::read_to_string(&valid_path).expect("failed to read valid detector TOML");
    assert_eq!(
        content_after_dry_run, valid_toml_content,
        "valid detector file must not be modified by dry-run"
    );

    // 2. Add an invalid detector TOML to the directory to test error reporting on dry-run
    let invalid_toml_content = r#"[detector]
id = "invalid-detector"
keywords = ["INVALID"]

[detector.verify]
url = "https://api.invalid.com/v1/{secret}"
"#;

    let invalid_path = temp_path.join("invalid-detector.toml");
    fs::write(&invalid_path, invalid_toml_content).expect("failed to write invalid detector TOML");

    let output_with_invalid = Command::new(binary())
        .args([
            "detectors",
            "--detectors",
            temp_path.to_str().unwrap(),
            "--fix",
            "--dry-run",
        ])
        .output()
        .expect("failed to run keyhog detectors with invalid detector file");

    assert!(
        !output_with_invalid.status.success(),
        "run with invalid detector must fail"
    );
    let stderr = String::from_utf8_lossy(&output_with_invalid.stderr);
    assert!(
        stderr.contains("could not safely rewrite"),
        "stderr must contain safe rewrite error message, got: {stderr}"
    );
    assert!(
        stderr.contains("invalid-detector"),
        "stderr must name the invalid detector file, got: {stderr}"
    );

    // Verify files remain unchanged
    let valid_content = fs::read_to_string(&valid_path).expect("failed to read valid detector");
    assert_eq!(
        valid_content, valid_toml_content,
        "valid file must remain unchanged on error"
    );
    let invalid_content =
        fs::read_to_string(&invalid_path).expect("failed to read invalid detector");
    assert_eq!(
        invalid_content, invalid_toml_content,
        "invalid file must remain unchanged on error"
    );

    // Clean up the invalid detector so we can perform the actual fix on the valid one
    fs::remove_file(invalid_path).expect("failed to remove invalid detector file");

    // 3. Run fix (without --dry-run) on valid detector
    let output_fix = Command::new(binary())
        .args([
            "detectors",
            "--detectors",
            temp_path.to_str().unwrap(),
            "--fix",
        ])
        .output()
        .expect("failed to run keyhog detectors --fix");

    assert!(
        output_fix.status.success(),
        "fix on valid detector must succeed"
    );
    let stdout_fix = String::from_utf8_lossy(&output_fix.stdout);
    assert!(
        stdout_fix.contains("fixed"),
        "stdout must mention the fix, got: {stdout_fix}"
    );
    assert!(
        stdout_fix.contains("Fix complete: 1 file(s) inspected, 1 updated, 1 total rewrite(s)."),
        "stdout must show expected fix complete summary, got: {stdout_fix}"
    );

    // Verify file content IS modified (single braces updated to double braces)
    let content_after_fix =
        fs::read_to_string(&valid_path).expect("failed to read valid detector TOML");
    assert!(
        content_after_fix.contains("url = \"https://api.valid.com/v1/{{secret}}\""),
        "single-brace must be rewritten to double-brace after fix; content is:\n{content_after_fix}"
    );
}
