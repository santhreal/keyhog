//! E2E: jsonl findings parse as objects with detector_id.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_jsonl_format_valid_objects() {
    let (_dir, path) = write_temp_file("planted.txt", "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n");
    let output = Command::new(binary()).args(["scan", "--no-daemon", "--format", "jsonl"]).arg(&path).output().expect("spawn");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().expect("one line");
    let obj = serde_json::from_str::<serde_json::Value>(line).expect("json object");
    assert!(obj.get("detector_id").is_some(), "jsonl object must have detector_id: {obj}");
}
