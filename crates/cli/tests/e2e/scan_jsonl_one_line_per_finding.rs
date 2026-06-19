//! E2E: `--format jsonl` emits one JSON object per line.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_jsonl_one_line_per_finding() {
    let (_dir, path) = write_temp_file(
        "planted.txt",
        "AWS_ACCESS_KEY.error_id = \"AKIAQYLPMN5HFIQR7XYA\"\n",
    );
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--format",
            "jsonl",
            "--backend",
            "simd",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "jsonl must emit at least one line");
    for line in &lines {
        serde_json::from_str::<serde_json::Value>(line).expect("each jsonl line must parse");
    }
}
