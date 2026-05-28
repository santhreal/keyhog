//! KH-GAP-108: Operator-facing errors cite `keyhog detectors list` but the CLI
//! has no `list` subcommand (clap rejects it with exit 2).

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn operator_errors_never_cite_phantom_detectors_list_subcommand() {
    let empty = TempDir::new().expect("tempdir");
    let scan = Command::new(binary())
        .args(["scan", ".", "--detectors"])
        .arg(empty.path())
        .output()
        .expect("spawn scan with empty detectors dir");
    let scan_err = String::from_utf8_lossy(&scan.stderr);
    assert!(
        !scan_err.contains("detectors list"),
        "scan errors must not cite phantom `keyhog detectors list`; stderr={scan_err}"
    );
}
