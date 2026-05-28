//! R5-T adversarial non-scan: scan-system rejects zero thread count.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn r5t_scan_system_zero_threads_rejected() {
    let output = Command::new(binary())
        .args(["scan-system", "--threads", "0"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
}
