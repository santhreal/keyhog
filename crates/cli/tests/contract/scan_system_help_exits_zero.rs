//! Contract: scan-system --help exits 0.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn scan_system_help_exits_zero() {
    let output = Command::new(binary())
        .args(["scan-system", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--space") && stdout.contains("--lockdown"),
        "scan-system help must document space and lockdown; got: {stdout}"
    );
}
