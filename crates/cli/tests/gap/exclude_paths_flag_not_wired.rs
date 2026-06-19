//! KH-GAP-011: `--exclude-paths` suppresses matching files from scan output.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn exclude_paths_flag_suppresses_matching_files() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("skip-me.env"),
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("keep-me.txt"), "hello\n").unwrap();

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
            "--exclude-paths",
            "skip-me.env",
            "--path",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");

    assert_eq!(
        output.status.code(),
        Some(0),
        "--exclude-paths must suppress the excluded secret file; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|_| serde_json::json!([]));
    assert!(
        findings.as_array().is_some_and(|a| a.is_empty()),
        "excluded file must produce zero findings; got: {stdout}"
    );
}
