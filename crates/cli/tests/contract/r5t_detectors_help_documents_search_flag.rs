//! R5-T contract: detectors --help documents --search.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_keyhog")) }

#[test]
fn r5t_detectors_help_documents_search_flag() {
    let output = Command::new(binary()).args(["detectors", "--help"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--search"),
        "detectors help must document --search; got: {stdout}"
    );
}
