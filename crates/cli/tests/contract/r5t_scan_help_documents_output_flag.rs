//! R5-T contract: scan --help documents --output.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_keyhog")) }

#[test]
fn r5t_scan_help_documents_output_flag() {
    let output = Command::new(binary()).args(["scan", "--help"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--output"),
        "scan help must document --output; got: {stdout}"
    );
}
