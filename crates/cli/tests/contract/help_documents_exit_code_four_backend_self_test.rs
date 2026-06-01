//! Contract: top-level --help documents exit code 4 (backend self-test).

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn help_documents_exit_code_four_backend_self_test() {
    let output = Command::new(binary())
        .arg("--help")
        .output()
        .expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("4") && combined.contains("backend"),
        "help must document exit 4 backend self-test; got: {combined}"
    );
}
