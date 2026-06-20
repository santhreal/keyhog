//! E2E: `--max-file-size` skips files above the threshold.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[path = "../support/json_report.rs"]
mod json_report_support;

use json_report_support::parse_json_array;

#[test]
fn scan_max_file_size_skips_oversized_file() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("large.txt");
    // 64 bytes of payload - above a 32-byte cap.
    std::fs::write(&path, "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n").unwrap();

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--no-daemon",
            "--format",
            "json",
            "--max-file-size",
            "1B",
            "--path",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");

    assert_eq!(
        output.status.code(),
        Some(0),
        "oversized file must be skipped (exit 0); stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains('\x1b'),
        "non-progress mode should not emit ANSI escapes; got: {}",
        stderr
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings = parse_json_array(&stdout, "max-file-size skipped scan JSON");
    assert!(
        findings.is_empty(),
        "skipped file must not produce findings; got: {}",
        stdout
    );
}
