//! Adversarial: diff with corrupt JSON baseline exits 2.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn diff_invalid_json_baseline_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let bad = dir.path().join("bad.json");
    std::fs::write(&bad, "not-json").unwrap();
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
        "stderr must cite JSON parse failure; got: {stderr}"
    );
}
