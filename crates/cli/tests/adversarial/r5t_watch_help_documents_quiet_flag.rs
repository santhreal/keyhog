//! R5-T adversarial non-scan: watch --help documents --quiet.

use crate::support::binary;
use std::process::Command;

#[test]
fn r5t_watch_help_documents_quiet_flag() {
    let output = Command::new(binary())
        .args(["watch", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--quiet"),
        "watch help must document --quiet; got: {stdout}"
    );
}
