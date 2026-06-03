//! Contract: `--help` documents exit code 2 (user error).
//!
//! AUD-coherence-3: `--help` previously labelled exit 2 "Runtime error" while
//! docs/src/reference/exit-codes.md, docs/src/first-scan.md, and the
//! `EXIT_USER_ERROR` constant in crates/cli/src/main.rs all call it a *user
//! error*. The help text now agrees with the documented contract, so this
//! contract asserts the documented wording rather than the stale one.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn help_documents_exit_code_two() {
    let output = Command::new(binary())
        .arg("--help")
        .output()
        .expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let lower = combined.to_lowercase();
    assert!(
        lower.contains("2   user error") || lower.contains("2  user error"),
        "help must document exit 2 as a user error (matching \
         docs/src/reference/exit-codes.md); got: {combined}"
    );
}
