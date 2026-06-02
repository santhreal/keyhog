//! Contract: `--format json` on a clean corpus emits an empty JSON array, not null.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_json_empty_corpus_empty_array() {
    // Write a file with no secrets and scan it
    let (_dir, path) = write_temp_file("clean.txt", "plain text, no secrets\n");
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--format", "json"])
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

    // Must be an array, not null
    assert!(
        value.is_array(),
        "json format must always emit an array, not null or object; got: {}",
        value.to_string()
    );

    // Must be empty
    let arr = value.as_array().expect("is an array");
    assert!(
        arr.is_empty(),
        "clean scan with --format json must emit an empty array [] ; got array with {} elements",
        arr.len()
    );

    // Verify the literal output is exactly [] with no extra whitespace/content
    let trimmed = stdout.trim();
    assert_eq!(
        trimmed, "[]",
        "json empty findings must be exactly '[]'; got: '{}'",
        trimmed
    );
}
