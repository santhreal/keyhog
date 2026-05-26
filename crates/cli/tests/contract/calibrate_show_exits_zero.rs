//! Contract: `calibrate --show` exits 0.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn calibrate_show_exits_zero() {
    let output = Command::new(binary()).args(["calibrate", "--show"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0), "calibrate --show must exit 0; stderr={}", String::from_utf8_lossy(&output.stderr));
}
