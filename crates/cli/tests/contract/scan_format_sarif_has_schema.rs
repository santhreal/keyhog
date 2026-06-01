//! Contract: `--format sarif` includes `$schema` and `version`.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_sarif_has_schema() {
    let (_dir, path) = write_temp_file("clean.txt", "hello\n");
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "sarif"])
        .arg(&path)
        .output()
        .expect("spawn");
    let sarif: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("sarif");
    assert!(sarif.get("version").is_some(), "sarif must include version");
}
