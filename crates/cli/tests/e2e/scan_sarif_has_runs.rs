//! E2E: `--format sarif` emits valid SARIF with runs.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_sarif_has_runs() {
    let (_dir, path) = write_temp_file(
        "planted.txt",
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n",
    );
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "sarif"])
        .arg(&path)
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("sarif json");
    assert!(
        sarif
            .get("runs")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty()),
        "sarif must have runs; got: {sarif}"
    );
}
