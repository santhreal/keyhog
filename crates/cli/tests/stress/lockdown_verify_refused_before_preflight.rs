//! R5-D2 / KH-GAP-165: `--lockdown --verify` must refuse with the verify
//! incompatibility message before coredump preflight masks it.

use crate::e2e::support::binary;
use std::process::Command;

#[test]
fn lockdown_verify_refused_before_preflight() {
    let output = Command::new(binary())
        .args(["scan", "--daemon=off", "--lockdown", "--verify", "."])
        .output()
        .expect("spawn");
    assert_eq!(
        output.status.code(),
        Some(2),
        "lockdown+verify must exit 2; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("lockdown mode forbids --verify"),
        "must cite verify incompatibility before coredump preflight; stderr={stderr}"
    );
}
