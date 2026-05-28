//! Contract: `--format json` on a clean file exits 0 with valid JSON array.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_json_clean_exit_zero() {
    let (_dir, path) = write_temp_file("clean.txt", "hello world\n");
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("json array");
    assert!(parsed.is_array());
}
