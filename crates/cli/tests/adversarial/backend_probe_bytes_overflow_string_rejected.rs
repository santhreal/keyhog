//! Adversarial: backend --probe-bytes non-numeric rejected at parse.

use crate::support::binary;
use std::process::Command;

#[test]
fn backend_probe_bytes_overflow_string_rejected() {
    let output = Command::new(binary())
        .args(["backend", "--probe-bytes", "not-a-number"])
        .output()
        .expect("spawn backend");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("probe-bytes") || stderr.contains("invalid value"),
        "bad --probe-bytes must fail at clap; got: {stderr}"
    );
}
