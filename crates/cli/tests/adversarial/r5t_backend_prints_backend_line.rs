//! R5-T adversarial non-scan: backend prints selected backend line.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn r5t_backend_prints_backend_line() {
    let output = Command::new(binary())
        .args(["backend"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("backend") || stdout.contains("Backend"),
        "backend subcommand must print backend info; got: {stdout}"
    );
}
