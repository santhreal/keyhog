//! Contract: scan --help documents --fast.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_keyhog")) }

#[test]
fn scan_help_documents_fast_flag() {
    let output = Command::new(binary()).args(["scan", "--help"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--fast"),
        "scan help must document --fast; got: {stdout}"
    );
}
