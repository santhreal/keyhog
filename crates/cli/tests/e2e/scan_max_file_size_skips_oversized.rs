//! E2E: `--max-file-size` skips files above the threshold.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn scan_max_file_size_skips_oversized_file() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("large.txt");
    // 64 bytes of payload - above a 32-byte cap.
    std::fs::write(&path, "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n").unwrap();

    let output = Command::new(binary())
        .args([
            "scan",
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
    let findings: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|_| serde_json::json!([]));
    assert!(
        findings.as_array().is_some_and(|a| a.is_empty()),
        "skipped file must not produce findings; got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
