//! Adversarial: diff identical corrupt baselines exits 2.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn diff_before_after_same_invalid_json() {
    let dir = TempDir::new().expect("tempdir");
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "{{not json").unwrap();
    let output = Command::new(binary())
        .args(["diff"])
        .arg(&bad)
        .arg(&bad)
        .output()
        .expect("spawn diff");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("json") || stderr.contains("parse") || stderr.contains("baseline"),
        "corrupt baseline must not succeed; got: {stderr}"
    );
}
