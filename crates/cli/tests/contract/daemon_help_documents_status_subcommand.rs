//! Contract: daemon --help documents status.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_keyhog")) }

#[test]
fn daemon_help_documents_status_subcommand() {
    let output = Command::new(binary()).args(["daemon", "--help"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("status"),
        "daemon help must document status; got: {stdout}"
    );
}
