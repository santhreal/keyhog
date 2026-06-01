//! Contract: calibrate --help exits 0.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn calibrate_help_exits_zero() {
    let output = Command::new(binary())
        .args(["calibrate", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--show") || stdout.contains("--tp"),
        "calibrate help must document counters; got: {stdout}"
    );
}
