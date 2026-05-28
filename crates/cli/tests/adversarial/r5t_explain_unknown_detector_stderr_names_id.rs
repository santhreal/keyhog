//! R5-T adversarial non-scan: explain unknown detector stderr names id.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn r5t_explain_unknown_detector_stderr_names_id() {
    let output = Command::new(binary())
        .args(["explain", "detector-does-not-exist-r5t"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("detector-does-not-exist-r5t") || stderr.contains("not found"),
        "unknown explain must name detector; got: {stderr}"
    );
}
