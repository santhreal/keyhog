//! Contract: `keyhog daemon --help` exits 0.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn daemon_help_exits_zero() {
    let output = Command::new(binary())
        .args(["daemon", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("start") && stdout.contains("stop"),
        "daemon help must document start/stop; got: {stdout}"
    );
}
