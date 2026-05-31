//! R5-T adversarial non-scan: detectors --json emits JSON array.

use crate::support::binary;
use std::process::Command;

#[test]
fn r5t_detectors_json_flag_emits_array() {
    let output = Command::new(binary())
        .args(["detectors", "--json"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let parsed: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("detectors --json");
    assert!(parsed.is_array());
    assert!(!parsed.as_array().unwrap().is_empty());
}
