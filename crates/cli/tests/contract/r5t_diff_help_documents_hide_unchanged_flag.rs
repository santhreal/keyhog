//! R5-T contract: diff --help documents --hide-unchanged.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_keyhog")) }

#[test]
fn r5t_diff_help_documents_hide_unchanged_flag() {
    let output = Command::new(binary()).args(["diff", "--help"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--hide-unchanged"),
        "diff help must document --hide-unchanged; got: {stdout}"
    );
}
