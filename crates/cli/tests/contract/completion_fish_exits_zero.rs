//! Contract: `keyhog completion fish` exits 0.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn completion_fish_exits_zero() {
    let output = Command::new(binary())
        .args(["completion", "fish"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("keyhog"),
        "fish completion must mention keyhog; got: {stdout}"
    );
}
