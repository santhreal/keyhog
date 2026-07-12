//! Contract: bogus `--severity` value exits 2 (user error).

use crate::e2e::support::binary;
use std::process::Command;

#[test]
fn invalid_severity_exits_two() {
    let output = Command::new(binary())
        .args(["scan", "--daemon=off", "--severity", "bogus", "."])
        .output()
        .expect("spawn");
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid severity must exit 2; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
