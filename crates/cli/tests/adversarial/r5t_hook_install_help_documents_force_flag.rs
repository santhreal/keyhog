//! R5-T adversarial non-scan: hook install --help documents --force.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn r5t_hook_install_help_documents_force_flag() {
    let output = Command::new(binary())
        .args(["hook", "install", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--force"), "hook install help must document --force; got: {stdout}");
}
