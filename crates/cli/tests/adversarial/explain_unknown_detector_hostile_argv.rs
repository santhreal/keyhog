//! Adversarial: explain with unknown detector id exits 2.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn explain_unknown_detector_hostile_argv() {
    let output = Command::new(binary())
        .args(["explain", "keyhog-adversarial-no-such-detector"])
        .output()
        .expect("spawn explain");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no detector") || stderr.contains("detectors"),
        "stderr must say detector missing; got: {stderr}"
    );
}
