//! R5-T adversarial non-scan: calibrate --help documents show subcommand.

use crate::adversarial::support::binary;
use std::process::Command;

#[test]
fn r5t_calibrate_help_documents_show_subcommand() {
    let output = Command::new(binary())
        .args(["calibrate", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("show"), "calibrate help must document show; got: {stdout}");
}
