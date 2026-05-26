//! Contract: `diff` with missing baseline file exits 2.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn diff_missing_file_exits_two() {
    let output = Command::new(binary()).args(["diff", "/nonexistent/keyhog-a", "/nonexistent/keyhog-b"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(2), "missing baseline must exit 2; stderr={}", String::from_utf8_lossy(&output.stderr));
}
