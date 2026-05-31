//! R5-T adversarial non-scan: scan-system --help documents --threads.

use crate::support::binary;
use std::process::Command;

#[test]
fn r5t_scan_system_help_documents_threads_flag() {
    let output = Command::new(binary())
        .args(["scan-system", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--threads"),
        "scan-system help must document --threads; got: {stdout}"
    );
}
