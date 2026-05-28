//! Contract: scan --help documents --git-staged.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_keyhog")) }

#[test]
fn scan_help_documents_git_staged_flag() {
    let output = Command::new(binary()).args(["scan", "--help"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--git-staged"),
        "scan help must document --git-staged; got: {stdout}"
    );
}
