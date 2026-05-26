//! Contract: conflicting baseline flags exit 2.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn scan_conflicting_baseline_flags_exits_two() {
    let output = Command::new(binary()).args(["scan", "--baseline", "a.json", "--create-baseline", "b.json", "."]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(2), "conflicting baseline flags must exit 2; stderr={}", String::from_utf8_lossy(&output.stderr));
}
