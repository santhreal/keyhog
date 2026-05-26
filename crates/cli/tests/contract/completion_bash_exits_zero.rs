//! Contract: `keyhog completion bash` exits 0 and emits shell script.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn completion_bash_exits_zero() {
    let output = Command::new(binary()).args(["completion", "bash"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("complete"), "bash completion must contain 'complete'; got: {stdout}");
}
