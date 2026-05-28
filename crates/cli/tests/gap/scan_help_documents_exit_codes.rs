//! KH-GAP-150: `keyhog scan --help` omitted EXIT CODES table present on
//! top-level `keyhog --help` — CI persona gap for exit-code discovery.

use crate::e2e::support::binary;
use std::process::Command;

#[test]
fn scan_subcommand_help_documents_exit_code_table() {
    let help = Command::new(binary())
        .args(["scan", "--help"])
        .output()
        .expect("spawn scan --help");
    assert_eq!(help.status.code(), Some(0));
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(
        text.contains("EXIT CODES"),
        "scan --help must document exit codes like top-level --help"
    );
    assert!(
        text.contains("Live credentials found"),
        "scan --help exit table must include exit 10 live-credentials row"
    );
}
