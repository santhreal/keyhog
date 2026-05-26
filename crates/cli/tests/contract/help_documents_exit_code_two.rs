//! Contract: `--help` documents exit code 2 (runtime error).

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn help_documents_exit_code_two() {
    let output = Command::new(binary()).arg("--help").output().expect("spawn");
    let combined = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(combined.contains("2   Runtime error") || combined.contains("2  Runtime error"), "help must document exit 2; got: {combined}");
}
