//! Adversarial: backend --patterns non-usize rejected.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn backend_patterns_non_numeric_rejected() {
    let output = Command::new(binary())
        .args(["backend", "--patterns", "not-a-usize"])
        .output()
        .expect("spawn backend --patterns");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("patterns") || stderr.contains("invalid value"),
        "bad --patterns must fail at clap; got: {stderr}"
    );
}
