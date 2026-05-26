//! Contract: `keyhog hook --help` exits 0.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn hook_help_exits_zero() {
    let output = Command::new(binary()).args(["hook", "--help"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("install") || stdout.contains("uninstall"), "hook help must document actions; got: {stdout}");
}
