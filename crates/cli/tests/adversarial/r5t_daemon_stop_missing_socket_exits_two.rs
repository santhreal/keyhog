//! R5-T adversarial non-scan: daemon stop on missing socket exits 2.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn r5t_daemon_stop_missing_socket_exits_two() {
    let output = Command::new(binary())
        .args(["daemon", "stop", "--socket", "/tmp/keyhog-r5t-stop-missing.sock"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
}
