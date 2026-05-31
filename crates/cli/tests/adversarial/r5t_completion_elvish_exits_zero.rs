//! R5-T adversarial non-scan: completion elvish emits script.

use crate::support::binary;
use std::process::Command;

#[test]
fn r5t_completion_elvish_exits_zero() {
    let output = Command::new(binary())
        .args(["completion", "elvish"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    assert!(!output.stdout.is_empty());
}
