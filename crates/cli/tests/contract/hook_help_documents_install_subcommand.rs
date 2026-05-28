//! Contract: hook --help documents install.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_keyhog")) }

#[test]
fn hook_help_documents_install_subcommand() {
    let output = Command::new(binary()).args(["hook", "--help"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("install"),
        "hook help must document install; got: {stdout}"
    );
}
