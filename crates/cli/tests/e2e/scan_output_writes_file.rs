//! E2E: `--output` writes findings JSON to disk.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;
use tempfile::TempDir;

#[test]
fn scan_output_writes_file() {
    let scan_dir = TempDir::new().expect("tempdir");
    let (_fdir, path) = write_temp_file(
        "planted.txt",
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n",
    );
    let out_path = scan_dir.path().join("findings.json");
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--format",
            "json",
            "--output",
        ])
        .arg(out_path.to_str().unwrap())
        .arg(&path)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(1));
    let written = std::fs::read_to_string(&out_path).expect("output file");
    let parsed = serde_json::from_str::<serde_json::Value>(&written).expect("json");
    let arr = parsed.as_array().expect("array");
    // Truth assert: the written file carries the REAL planted AWS finding, proving
    // --output persisted actual findings (not an empty/junk array) to disk.
    assert!(
        arr.iter().any(|f| matches!(
            f.get("detector_id").and_then(|v| v.as_str()),
            Some("aws-access-key" | "hot-aws_key")
        )),
        "--output file must contain the planted AWS finding; got {arr:?}"
    );
}
