//! Contract: incompatible `--lockdown --verify` exits 2.

use crate::e2e::support::binary;
use std::process::Command;

#[test]
fn scan_lockdown_verify_exits_two() {
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
        "must refuse verify before scan; stderr={stderr}"
    );
}
