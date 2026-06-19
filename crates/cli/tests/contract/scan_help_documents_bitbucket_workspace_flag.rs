//! Contract: scan --help documents --bitbucket-workspace.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn scan_help_documents_bitbucket_workspace_flag() {
    let output = Command::new(binary())
        .args(["scan", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--bitbucket-workspace"),
        "scan help must document --bitbucket-workspace; got: {stdout}"
    );
    assert!(
        stdout.contains("--bitbucket-username") && stdout.contains("--bitbucket-token"),
        "scan help must document Bitbucket auth flags; got: {stdout}"
    );
}
