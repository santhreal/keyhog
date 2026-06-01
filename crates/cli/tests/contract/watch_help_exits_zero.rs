//! Contract: watch --help exits 0.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn watch_help_exits_zero() {
    let output = Command::new(binary())
        .args(["watch", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--quiet") || stdout.contains("watch"),
        "watch help must document flags; got: {stdout}"
    );
}
