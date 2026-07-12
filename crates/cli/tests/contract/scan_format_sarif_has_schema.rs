//! Contract: `--format sarif` includes `$schema` and `version`.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_format_sarif_has_schema() {
    let (_dir, path) = write_temp_file("clean.txt", "hello\n");
    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--backend",
            "simd",
            "--format",
            "sarif",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    let sarif: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("sarif");
    // Law 6: pin the actual contract values, not just key presence. SARIF
    // consumers (GitHub code scanning, SIEMs) key off exactly these.
    assert_eq!(
        sarif["version"].as_str(),
        Some("2.1.0"),
        "sarif version must be exactly 2.1.0; got {sarif}"
    );
    let schema = sarif["$schema"]
        .as_str()
        .expect("sarif must include a $schema URL");
    assert!(
        schema.contains("sarif") && schema.contains("2.1.0"),
        "$schema must reference the SARIF 2.1.0 schema; got {schema}"
    );
}
