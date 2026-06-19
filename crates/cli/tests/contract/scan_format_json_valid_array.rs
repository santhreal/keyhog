//! Contract: `--format json` stdout is always a JSON array.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_json_valid_array() {
    let (_dir, path) = write_temp_file("note.txt", "plain text\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "json",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    let parsed: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("json");
    assert!(parsed.is_array(), "json format must emit an array");
}
