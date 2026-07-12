//! E2E: jsonl findings parse as objects with detector_id.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_jsonl_format_valid_objects() {
    let (_dir, path) = write_temp_file(
        "planted.txt",
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n",
    );
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--format",
            "jsonl",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Law 6: pin the actual detector_id VALUE across the emitted lines, not just
    // that the key is present. The planted AWS key must surface as aws-access-key.
    let ids: Vec<String> = stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .expect("each jsonl line must be a json object")
                .get("detector_id")
                .and_then(|v| v.as_str())
                .expect("each jsonl object must have a detector_id")
                .to_string()
        })
        .collect();
    assert!(
        ids.iter().any(|id| id == "aws-access-key"),
        "planted AWS key must surface as aws-access-key; got {ids:?}"
    );
}
