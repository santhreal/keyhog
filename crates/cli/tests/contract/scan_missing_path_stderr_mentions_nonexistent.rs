//! Contract: missing scan path writes actionable stderr (not silent success).

use crate::e2e::support::binary;
use std::process::Command;

#[test]
fn scan_missing_path_stderr_mentions_nonexistent() {
    let missing = "/nonexistent/keyhog-contract-missing-xyzzy";
    let output = Command::new(binary())
        .args(["scan", "--daemon=off", missing])
        .output()
        .expect("spawn");
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    assert_ne!(output.status.code(), Some(0));
    assert!(
        stderr.contains("does not exist")
            || stderr.contains("not found")
            || stderr.contains("nonexistent"),
        "stderr must explain missing path; got: {stderr}"
    );
}
