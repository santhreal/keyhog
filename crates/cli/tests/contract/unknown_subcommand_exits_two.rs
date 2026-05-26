//! Contract: unrecognized subcommand exits 2 (user error).

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn unknown_subcommand_exits_two() {
    let output = Command::new(binary()).arg("not-a-command").output().expect("spawn");
    assert_eq!(output.status.code(), Some(2), "unknown subcommand must exit 2; stderr={}", String::from_utf8_lossy(&output.stderr));
}
