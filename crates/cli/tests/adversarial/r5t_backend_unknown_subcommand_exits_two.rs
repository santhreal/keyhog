//! R5-T adversarial non-scan: backend rejects unknown trailing arg.

use crate::support::binary;
use std::process::Command;

#[test]
fn r5t_backend_unknown_subcommand_exits_two() {
    let output = Command::new(binary())
        .args(["backend", "--totally-invalid-r5t-flag"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
}
