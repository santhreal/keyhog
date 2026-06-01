//! Contract: scan --help documents --no-daemon.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn scan_help_documents_no_daemon_flag() {
    let output = Command::new(binary())
        .args(["scan", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--no-daemon"),
        "scan help must document --no-daemon; got: {stdout}"
    );
}
