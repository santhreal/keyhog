//! Contract: `--help` documents exit code 4 (health / self-test failure).
//!
//! AUD-coherence-2: `--help` previously described exit 4 as ONLY a
//! `backend --self-test` failure, silently dropping the `keyhog repair` (and
//! `keyhog doctor`) producers that docs/src/reference/exit-codes.md documents
//! and that crates/cli/src/subcommands/repair.rs (EXIT_REPAIR_FAILED = 4)
//! emits. The help text now describes the full exit-4 contract, so this
//! contract asserts that the exit-4 line acknowledges both the backend
//! self-test and the repair producers.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn help_documents_exit_code_four() {
    let output = Command::new(binary())
        .arg("--help")
        .output()
        .expect("spawn");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let exit4_line = combined
        .lines()
        .find(|l| {
            l.trim_start()
                .split_whitespace()
                .next()
                .map(|t| t == "4")
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no exit-code-4 line found in --help; got: {combined}"))
        .to_lowercase();
    assert!(
        exit4_line.contains("backend") && exit4_line.contains("repair"),
        "help exit-4 line must document the full health/self-test contract \
         (backend self-test + repair), matching docs/src/reference/exit-codes.md; \
         got: {exit4_line:?}"
    );
}
