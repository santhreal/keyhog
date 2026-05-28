//! Adversarial: diff with missing after file exits 2.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn diff_after_file_missing_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let before = dir.path().join("before.json");
    std::fs::write(&before, "[]").unwrap();
    let output = Command::new(binary())
        .args(["diff"])
        .arg(&before)
        .arg("/nonexistent/keyhog-adversarial-after.json")
        .output()
        .expect("spawn diff");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("baseline") || stderr.contains("No such file"),
        "missing after baseline must fail; got: {stderr}"
    );
}
