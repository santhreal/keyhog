//! R5-T contract: diff --help documents --json.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn r5t_diff_help_documents_json_flag() {
    let output = Command::new(binary())
        .args(["diff", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--json"),
        "diff help must document --json; got: {stdout}"
    );
}
