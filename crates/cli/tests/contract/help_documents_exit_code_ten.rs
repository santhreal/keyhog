//! Contract: `--help` documents exit code 10 (live credentials).

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn help_documents_exit_code_ten() {
    let output = Command::new(binary()).arg("--help").output().expect("spawn");
    let combined = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(combined.contains("10  Live credentials"), "help must document exit 10; got: {combined}");
}
