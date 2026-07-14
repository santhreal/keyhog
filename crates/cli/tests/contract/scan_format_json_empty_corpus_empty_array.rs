//! Contract: `--format json-envelope` on a clean corpus emits an empty versioned envelope.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_json_empty_corpus_empty_array() {
    // Write a file with no secrets and scan it
    let (_dir, path) = write_temp_file("clean.txt", "plain text, no secrets\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "json-envelope",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(
        output.status.code(),
        Some(0),
        "clean scan must exit 0 (no findings)"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("json must be valid");

    let object = value.as_object().expect("json format must emit an object");
    assert_eq!(object["schema_version"]["major"], 1);
    let arr = object["findings"].as_array().expect("findings array");
    assert!(
        arr.is_empty(),
        "clean scan with --format json must emit an empty findings array; got {} elements",
        arr.len()
    );
}
