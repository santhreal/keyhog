//! Contract: `--exclude-paths` suppresses findings from excluded files.

use crate::support::binary;
use keyhog::exit_codes::EXIT_SOURCE_FAILED;
use std::process::Command;
use tempfile::TempDir;

#[path = "../support/json_report.rs"]
mod json_report_support;

use json_report_support::parse_json_array;

#[test]
fn all_excluded_input_fails_closed_without_findings() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("skip.env"),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .unwrap();
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            crate::support::DIAGNOSTIC_BACKEND,
            "--format",
            "json",
            "--exclude-paths",
            "skip.env",
            "--no-suppress-test-fixtures",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");
    assert_eq!(
        output.status.code(),
        Some(i32::from(EXIT_SOURCE_FAILED)),
        "excluding every candidate must not report a clean scan"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings = parse_json_array(&stdout, "exclude-paths contract scan JSON");
    assert!(findings.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("This scan read ZERO bytes"),
        "zero-byte exclusion failure must explain the coverage gap: {stderr}"
    );
}
