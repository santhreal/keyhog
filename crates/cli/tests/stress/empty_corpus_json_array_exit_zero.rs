//! R5-D2 / KH-GAP-173: empty directory corpus exits 0 with JSON `[]`.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn empty_corpus_json_array_exit_zero() {
    let dir = TempDir::new().expect("tempdir");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
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
