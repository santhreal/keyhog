//! R5-T contract: scan --help documents --exclude-paths.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_keyhog")) }

#[test]
fn r5t_scan_help_documents_exclude_paths_flag() {
    let output = Command::new(binary()).args(["scan", "--help"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--exclude-paths"),
        "scan help must document --exclude-paths; got: {stdout}"
    );
}
