//! Adversarial: scan-system rejects unknown --space suffix.

use crate::adversarial::support::{binary, workspace_detectors};
use std::process::Command;

#[test]
fn scan_system_invalid_space_unit_exits_two() {
    let output = Command::new(binary())
        .args([
            "scan-system",
            "--space",
            "10XY",
            "--detectors",
            workspace_detectors().to_str().expect("detectors"),
        ])
        .output()
        .expect("spawn scan-system");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("space") || stderr.contains("suffix") || stderr.contains("invalid value"),
        "stderr must reject bad --space; got: {stderr}"
    );
}
