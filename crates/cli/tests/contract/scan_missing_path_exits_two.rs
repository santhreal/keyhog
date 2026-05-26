//! Contract: scan of non-existent path exits 2 (user error).

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn scan_missing_path_exits_two() {
    let output = Command::new(binary()).args(["scan", "/nonexistent/keyhog-missing-path-xyzzy"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(2), "missing path must exit 2; stderr={}", String::from_utf8_lossy(&output.stderr));
}
