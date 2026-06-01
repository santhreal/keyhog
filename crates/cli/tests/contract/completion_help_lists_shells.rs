//! Contract: completion --help lists supported shells.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn completion_help_lists_shells() {
    let output = Command::new(binary())
        .args(["completion", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("bash") && stdout.contains("zsh"),
        "completion help must list shells; got: {stdout}"
    );
}
