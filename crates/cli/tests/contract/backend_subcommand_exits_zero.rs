//! Contract: `keyhog backend` exits 0 and prints routing info.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn backend_subcommand_exits_zero() {
    let output = Command::new(binary()).arg("backend").output().expect("spawn");
    assert_eq!(output.status.code(), Some(0), "backend must exit 0; stderr={}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.to_lowercase().contains("backend") || stdout.contains("KEYHOG"), "backend output expected routing info; got: {stdout}");
}
