//! R5-T adversarial non-scan: daemon start --help documents --socket.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn r5t_daemon_start_help_documents_socket_flag() {
    let output = Command::new(binary())
        .args(["daemon", "start", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--socket"), "daemon start help must document --socket; got: {stdout}");
}
