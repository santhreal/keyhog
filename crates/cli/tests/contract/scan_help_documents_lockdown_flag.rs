//! Contract: scan --help documents --lockdown.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn scan_help_documents_lockdown_flag() {
    let output = Command::new(binary())
        .args(["scan", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--lockdown"),
        "scan help must document --lockdown; got: {stdout}"
    );
}
