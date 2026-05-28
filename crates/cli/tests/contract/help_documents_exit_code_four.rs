//! Contract: `--help` documents exit code 4 (`backend --self-test` failure).

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn help_documents_exit_code_four() {
    let output = Command::new(binary()).arg("--help").output().expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("4   `backend --self-test` failed")
            || combined.contains("4  `backend --self-test` failed")
            || combined.contains("4   backend --self-test")
            || combined.contains("4  backend --self-test"),
        "help must document exit 4; got: {combined}"
    );
}
