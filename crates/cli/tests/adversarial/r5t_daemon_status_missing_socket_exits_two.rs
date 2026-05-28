//! R5-T adversarial non-scan: daemon status on missing socket path fails loudly.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn r5t_daemon_status_missing_socket_exits_two() {
    let output = Command::new(binary())
        .args(["daemon", "status", "--socket", "/tmp/keyhog-r5t-nonexistent.sock"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("socket") || stderr.contains("No such file") || stderr.contains("connect"),
        "missing daemon socket must fail; got: {stderr}"
    );
}
