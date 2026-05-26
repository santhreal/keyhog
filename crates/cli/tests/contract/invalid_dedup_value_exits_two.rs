//! Contract: invalid `--dedup` value exits 2.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn invalid_dedup_value_exits_two() {
    let output = Command::new(binary()).args(["scan", "--dedup", "not-a-scope", "."]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(2), "invalid dedup must exit 2; stderr={}", String::from_utf8_lossy(&output.stderr));
}
