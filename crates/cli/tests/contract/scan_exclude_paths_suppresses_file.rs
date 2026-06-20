//! Contract: `--exclude-paths` suppresses findings from excluded files.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[path = "../support/json_report.rs"]
mod json_report_support;

use json_report_support::parse_json_array;

#[test]
fn scan_exclude_paths_suppresses_file() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("skip.env"),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .unwrap();
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
            "--exclude-paths",
            "skip.env",
            "--no-suppress-test-fixtures",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings = parse_json_array(&stdout, "exclude-paths contract scan JSON");
    assert!(findings.is_empty());
}
