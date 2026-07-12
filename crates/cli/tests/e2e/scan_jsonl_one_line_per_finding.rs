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
            "--daemon=off",
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
    // Law 6: every jsonl line is a real finding object carrying a detector_id,
    // and the planted AWS key must surface specifically as `aws-access-key` —
    // not merely "some line that parses".
    let detector_ids: Vec<String> = lines
        .iter()
        .map(|line| {
            let obj = serde_json::from_str::<serde_json::Value>(line)
                .expect("each jsonl line must parse");
            obj.get("detector_id")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("each jsonl finding must carry a detector_id: {obj}"))
                .to_string()
        })
        .collect();
    assert!(
        detector_ids.iter().any(|id| id == "aws-access-key"),
        "the planted AWS key must surface as aws-access-key; got {detector_ids:?}"
    );
}
