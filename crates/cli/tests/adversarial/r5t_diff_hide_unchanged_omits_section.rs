//! R5-T adversarial non-scan: diff --hide-unchanged omits unchanged entries.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn r5t_diff_hide_unchanged_omits_section() {
    let dir = TempDir::new().expect("tempdir");
    let baseline = dir.path().join("base.json");
    std::fs::write(&baseline, r#"{"version":1,"entries":[]}"#).unwrap();
    let output = Command::new(binary())
        .args(["diff", "--json", "--hide-unchanged"])
        .arg(&baseline)
        .arg(&baseline)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert!(parsed.get("unchanged").unwrap().is_null());
}
