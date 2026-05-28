//! Adversarial: daemon status with no server must exit 2.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn daemon_status_without_running_daemon_fails() {
    let output = Command::new(binary())
        .args(["daemon", "status"])
        .output()
        .expect("spawn daemon status");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("daemon") && stderr.contains("no daemon"),
        "stderr must state no daemon; got: {stderr}"
    );
}
