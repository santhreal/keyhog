//! Adversarial: daemon start --help documents --socket without starting server.

use crate::support::binary;
use std::process::Command;

#[test]
fn daemon_start_help_documents_socket_flag() {
    let output = Command::new(binary())
        .args(["daemon", "start", "--help"])
        .output()
        .expect("spawn daemon start --help");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--socket") && stdout.contains("detectors"),
        "daemon start help must document socket and detectors; got: {stdout}"
    );
}
