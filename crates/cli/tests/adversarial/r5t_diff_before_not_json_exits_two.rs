//! R5-T adversarial non-scan: diff rejects non-JSON before file.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn r5t_diff_before_not_json_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let before = dir.path().join("before.txt");
    let after = dir.path().join("after.json");
    std::fs::write(&before, "not json").unwrap();
    std::fs::write(&after, r#"{"version":1,"entries":[]}"#).unwrap();
    let output = Command::new(binary())
        .args(["diff"])
        .arg(&before)
        .arg(&after)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.is_empty(), "invalid before baseline must explain failure");
}
