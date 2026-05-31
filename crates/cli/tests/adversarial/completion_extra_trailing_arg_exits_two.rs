//! Adversarial: completion with extra trailing arg exits 2.

use crate::support::binary;
use std::process::Command;

#[test]
fn completion_extra_trailing_arg_exits_two() {
    let output = Command::new(binary())
        .args(["completion", "bash", "extra-hostile-arg"])
        .output()
        .expect("spawn completion");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected")
            || stderr.contains("unrecognized")
            || stderr.contains("Usage"),
        "extra completion arg must fail; got: {stderr}"
    );
}
