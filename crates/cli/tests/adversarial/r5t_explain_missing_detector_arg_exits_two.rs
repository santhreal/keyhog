//! R5-T adversarial non-scan: explain without detector id exits 2.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn r5t_explain_missing_detector_arg_exits_two() {
    let output = Command::new(binary())
        .args(["explain"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
}
