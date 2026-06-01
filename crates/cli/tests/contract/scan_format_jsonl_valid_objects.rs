//! Contract: `--format jsonl` emits one JSON object per finding line.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_jsonl_valid_objects() {
    let (_dir, path) = write_temp_file("secret.env", "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--format",
            "jsonl",
            "--no-suppress-test-fixtures",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    for line in String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty())
    {
        let obj: serde_json::Value = serde_json::from_str(line).expect("jsonl object");
        assert!(obj.is_object(), "each jsonl line must be an object");
    }
}
