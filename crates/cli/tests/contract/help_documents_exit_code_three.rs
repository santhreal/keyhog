//! Contract: `--help` documents exit code 3 (system error).

use crate::e2e::support::binary;
use std::process::Command;

#[test]
fn help_documents_exit_code_three() {
    let output = Command::new(binary()).arg("--help").output().expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("3   System error") || combined.contains("3  System error"),
        "help must document exit 3; got: {combined}"
    );
}
