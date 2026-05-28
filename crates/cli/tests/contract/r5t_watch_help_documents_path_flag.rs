//! R5-T contract: watch --help documents <PATH>.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_keyhog")) }

#[test]
fn r5t_watch_help_documents_path_flag() {
    let output = Command::new(binary()).args(["watch", "--help"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("<PATH>"),
        "watch help must document <PATH>; got: {stdout}"
    );
}
