//! Contract: missing scan path exits 2 and prints actionable stderr.

use crate::e2e::support::binary;
use std::process::Command;

#[test]
fn scan_missing_path_stderr_nonempty() {
    let missing = "/nonexistent/keyhog-contract-stderr-empty";
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", missing])
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(2),
        "missing path must exit 2; stderr={stderr}"
    );
    assert!(
        stderr.contains("does not exist"),
        "stderr must explain missing path; got: {stderr}"
    );
}
