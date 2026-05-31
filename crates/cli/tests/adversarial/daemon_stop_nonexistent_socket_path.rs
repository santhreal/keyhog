//! Adversarial: daemon stop --socket on missing socket exits 2.

use crate::support::binary;
use std::process::Command;

#[test]
fn daemon_stop_nonexistent_socket_path() {
    let output = Command::new(binary())
        .args(["daemon", "stop", "--socket", "/nonexistent/keyhog.sock"])
        .output()
        .expect("spawn daemon stop --socket");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("daemon") || stderr.contains("no daemon"),
        "missing socket must fail; got: {stderr}"
    );
}
