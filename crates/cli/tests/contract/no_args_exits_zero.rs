//! Contract: invoking keyhog with no subcommand prints help and exits 0.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn no_args_exits_zero() {
    let output = Command::new(binary()).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0), "no-args must exit 0; stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage:"), "no-args must print usage; got: {stdout}");
}
