//! R5-T contract: detectors --help documents the canonical --format flag.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn r5t_detectors_help_documents_format_flag() {
    let output = Command::new(binary())
        .args(["detectors", "--help"])
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--format <FORMAT>") && stdout.contains("text, json"),
        "detectors help must document --format and its values; got: {stdout}"
    );
    assert!(
        !stdout.contains("--json"),
        "detectors help must not advertise the compatibility spelling; got: {stdout}"
    );
}
