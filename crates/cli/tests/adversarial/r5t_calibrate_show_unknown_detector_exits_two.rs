//! R5-T adversarial non-scan: calibrate show unknown detector exits 2.

use crate::support::binary;
use std::process::Command;

#[test]
fn r5t_calibrate_show_unknown_detector_exits_two() {
    let output = Command::new(binary())
        .args(["calibrate", "show", "no-such-detector-r5t-xyz"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
}
