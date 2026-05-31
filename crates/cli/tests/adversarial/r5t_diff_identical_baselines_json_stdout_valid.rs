//! R5-T adversarial non-scan: diff identical baselines emits valid JSON with --json.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn r5t_diff_identical_baselines_json_stdout_valid() {
    let dir = TempDir::new().expect("tempdir");
    let baseline = dir.path().join("base.json");
    std::fs::write(&baseline, r#"{"version":1,"entries":[]}"#).unwrap();
    let output = Command::new(binary())
        .args(["diff", "--json"])
        .arg(&baseline)
        .arg(&baseline)
        .output()
        .expect("spawn diff");
    assert_eq!(output.status.code(), Some(0));
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("diff --json must emit valid JSON");
    assert_eq!(parsed["summary"]["new"].as_u64(), Some(0));
    assert_eq!(parsed["summary"]["resolved"].as_u64(), Some(0));
}
