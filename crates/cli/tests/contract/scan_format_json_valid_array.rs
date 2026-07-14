//! Contract: `--format json` stdout is a versioned findings envelope.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_json_valid_array() {
    let (_dir, path) = write_temp_file("note.txt", "plain text\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
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
    let object = parsed.as_object().expect("json format must emit an object");
    assert_eq!(object["schema_version"]["major"], 1);
    assert!(object["schema_version"]["minor"].is_u64());
    assert!(object["findings"].is_array());
}
