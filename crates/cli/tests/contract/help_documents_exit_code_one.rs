//! Contract: `--help` documents exit code 1 (findings).

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn help_documents_exit_code_one() {
    let output = Command::new(binary()).arg("--help").output().expect("spawn");
    let combined = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(combined.contains("1   Secrets found") || combined.contains("1  Secrets found"), "help must document exit 1; got: {combined}");
}
