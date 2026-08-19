//! Contract: `--help` documents exit code 4 (health / self-test failure).
//!
//! `--help` once described exit 4 as ONLY a `backend --self-test` failure,
//! silently dropping the other producers that
//! docs/src/reference/exit-codes.md documents. `keyhog repair` was one of
//! them until the binary-asset release channel it drove was retired; `doctor`
//! and `backend --self-test` remain. The help text must name every surviving
//! producer, so this asserts the exit-4 line acknowledges both.

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
        exit4_line.contains("doctor") && exit4_line.contains("backend"),
        "help exit-4 line must document every surviving health/self-test \
         producer (doctor unhealthy + backend self-test), matching \
         docs/src/reference/exit-codes.md; got: {exit4_line:?}"
    );
}
