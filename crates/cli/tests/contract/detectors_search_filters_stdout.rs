//! Contract: `detectors --search aws` filters output to AWS-related detectors.

use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn detectors_search_filters_stdout() {
    let output = Command::new(binary()).args(["detectors", "--search", "aws"]).output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(stdout.contains("aws"), "filtered detectors must mention aws; got: {stdout}");
}
