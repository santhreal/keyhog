//! KH-GAP-011: `--exclude-paths` suppresses matching files from scan output.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[path = "../support/json_report.rs"]
mod json_report_support;

use json_report_support::parse_json_array;

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
            "--daemon=off",
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
    let findings = parse_json_array(&stdout, "exclude-paths gap scan JSON");
    assert!(
        findings.is_empty(),
        "excluded file must produce zero findings; got: {stdout}"
    );
}
