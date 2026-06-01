//! Contract: `--exclude-paths` suppresses findings from excluded files.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

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
    let findings: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout))
            .unwrap_or(serde_json::json!([]));
    assert!(findings.as_array().is_some_and(|a| a.is_empty()));
}
