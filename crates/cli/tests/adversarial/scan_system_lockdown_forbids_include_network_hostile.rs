//! Adversarial: scan-system lockdown + include-network must fail closed.

use crate::adversarial::support::{binary, workspace_detectors};
use std::process::Command;

#[test]
fn scan_system_lockdown_forbids_include_network_hostile() {
    let output = Command::new(binary())
        .args([
            "scan-system",
            "--lockdown",
            "--include-network",
            "--detectors",
            workspace_detectors().to_str().expect("detectors path"),
        ])
        .output()
        .expect("spawn scan-system");
    assert_ne!(output.status.code(), Some(0));
    let combined = format!(
        "{}
{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("lockdown") || combined.contains("include-network"),
        "scan-system lockdown+network must fail closed; got: {combined}"
    );
}
