//! E2E: `--format sarif` emits valid SARIF with runs.

use crate::e2e::support::{binary, write_temp_file};
use std::process::Command;

#[test]
fn scan_sarif_has_runs() {
    let (_dir, path) = write_temp_file(
        "planted.txt",
        "AWS_ACCESS_KEY_ID = \"AKIAQYLPMN5HFIQR7XYA\"\n",
    );
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--format",
            "sarif",
            "--backend",
            "simd",
        ])
        .arg(&path)
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("sarif json");
    assert!(
        sarif
            .get("runs")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty()),
        "sarif must have runs; got: {sarif}"
    );
    // Law 6: pin the full SARIF envelope identity + the concrete result, not just
    // a present `runs` array. SARIF consumers (GitHub code scanning, SIEMs) key
    // off exactly these values.
    assert_eq!(
        sarif["version"], "2.1.0",
        "SARIF version must be exactly 2.1.0; got: {sarif}"
    );
    assert_eq!(
        sarif["$schema"],
        "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1.0/sarif-schema-2.1.0.json",
        "SARIF must carry the OASIS 2.1.0 $schema URL; got: {sarif}"
    );
    assert_eq!(
        sarif["runs"][0]["tool"]["driver"]["name"], "keyhog",
        "runs[0].tool.driver.name must identify the keyhog driver; got: {sarif}"
    );
    // The planted AWS key must surface as a concrete result whose ruleId is the
    // real detector id, parsed from the SARIF structure (not a stdout substring).
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("runs[0].results must be an array");
    assert!(
        results.iter().any(|r| r["ruleId"] == "aws-access-key"),
        "the planted AWS key must surface as a SARIF result with ruleId aws-access-key; got: {sarif}"
    );
}
