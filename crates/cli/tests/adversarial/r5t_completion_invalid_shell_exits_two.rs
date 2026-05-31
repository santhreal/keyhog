//! R5-T adversarial non-scan: completion rejects unknown shell name.

use crate::support::binary;
use std::process::Command;

#[test]
fn r5t_completion_invalid_shell_exits_two() {
    let output = Command::new(binary())
        .args(["completion", "not-a-real-shell-r5t"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
}
