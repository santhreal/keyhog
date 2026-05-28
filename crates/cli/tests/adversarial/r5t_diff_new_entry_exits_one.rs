//! R5-T adversarial non-scan: diff reports exit 1 when after has NEW entries.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn r5t_diff_new_entry_exits_one() {
    let dir = TempDir::new().expect("tempdir");
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    std::fs::write(&before, r#"{"version":1,"entries":[]}"#).unwrap();
    std::fs::write(
        &after,
        r#"{"version":1,"entries":[{"detector_id":"aws-access-key","credential_hash":"abc","path":"x","line":1}]}"#,
    )
    .unwrap();
    let output = Command::new(binary())
        .args(["diff", "--json"])
        .arg(&before)
        .arg(&after)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(1));
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(parsed["summary"]["new"].as_u64(), Some(1));
}
