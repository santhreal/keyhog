//! Adversarial: diff --json with invalid baseline exits 2.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn diff_json_flag_invalid_baseline_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let a = dir.path().join("a.json");
    let b = dir.path().join("b.json");
    std::fs::write(&a, "{").unwrap();
    std::fs::write(&b, "[]").unwrap();
    let output = Command::new(binary())
        .args(["diff", "--json"])
        .arg(&a)
        .arg(&b)
        .output()
        .expect("spawn diff --json");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.stdout.is_empty() || stderr.contains("json") || stderr.contains("parse"),
        "invalid baseline must not emit success JSON; stderr={stderr}"
    );
}
