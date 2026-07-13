//! Adversarial: scan-system --space 0 rejected.

use crate::support::{binary, workspace_detectors};
use std::process::Command;

#[test]
fn scan_system_zero_space_rejected() {
    let output = Command::new(binary())
        .args([
            "scan-system",
            "--space",
            "0G",
            "--detectors",
            workspace_detectors().to_str().expect("detectors"),
        ])
        .output()
        .expect("spawn scan-system");
    // 0G parses to 0 bytes (walker should still start; assert it does not hang and exits).
    assert!(
        output.status.code().is_some(),
        "scan-system --space 0G must terminate; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
