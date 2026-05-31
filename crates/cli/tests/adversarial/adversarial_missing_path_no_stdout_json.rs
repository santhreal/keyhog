//! Adversarial: missing path must not print a fake `[]` success JSON body.

use crate::support::binary;
use std::process::Command;

#[test]
fn adversarial_missing_path_no_stdout_json() {
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--format",
            "json",
            "/nonexistent/keyhog-adversarial-missing",
        ])
        .output()
        .expect("spawn");
    assert_ne!(output.status.code(), Some(0));
    let stdout_owned = String::from_utf8_lossy(&output.stdout).into_owned();
    let stdout = stdout_owned.trim();
    assert_ne!(
        stdout, "[]",
        "missing path must not masquerade as clean JSON"
    );
}
