//! Adversarial: diff with missing before file exits 2.

use crate::support::binary;
use std::process::Command;

#[test]
fn diff_before_file_missing_exits_two() {
    let output = Command::new(binary())
        .args([
            "diff",
            "/nonexistent/keyhog-adversarial-before.json",
            "/nonexistent/keyhog-adversarial-after.json",
        ])
        .output()
        .expect("spawn diff");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("baseline") || stderr.contains("No such file"),
        "stderr must cite missing baseline; got: {stderr}"
    );
}
