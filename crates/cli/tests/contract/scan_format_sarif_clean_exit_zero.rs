//! Contract: `--format sarif` on a clean file exits 0 with SARIF object.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_sarif_clean_exit_zero() {
    let (_dir, path) = write_temp_file("clean.txt", "hello world\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--backend",
            "simd",
            "--format",
            "sarif",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let sarif: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("sarif json");
    // Law 6: a clean scan still emits a well-formed SARIF 2.1.0 document with a
    // run whose results array is present and EMPTY — not merely "runs exists".
    assert_eq!(
        sarif["version"].as_str(),
        Some("2.1.0"),
        "SARIF version must be 2.1.0; got {sarif}"
    );
    let runs = sarif["runs"]
        .as_array()
        .expect("SARIF must carry a runs array");
    assert!(
        !runs.is_empty(),
        "SARIF must have at least one run; got {sarif}"
    );
    let results = runs[0]["results"]
        .as_array()
        .expect("run must carry a results array");
    assert!(
        results.is_empty(),
        "a clean scan (exit 0) must produce zero SARIF results; got {results:?}"
    );
}
