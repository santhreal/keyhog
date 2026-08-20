//! R5-D2 / KH-GAP-173: empty directory corpus exits 0 with JSON `[]`.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn empty_corpus_json_array_exit_zero() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("clean.txt"), "plain text, no secrets\n")
        .expect("write clean file");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            crate::support::DIAGNOSTIC_BACKEND,
            "--format",
            "json",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");

    assert_eq!(
        output.status.code(),
        Some(0),
        "empty corpus must exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "[]",
        "empty corpus must emit JSON array"
    );
}
