//! Adversarial: explain --detectors pointing at file fails.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn explain_detectors_path_is_file_fails() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("det.toml");
    std::fs::write(&file, "id = \"x\"\n").unwrap();
    let output = Command::new(binary())
        .args(["explain", "aws-access-key", "--detectors"])
        .arg(&file)
        .output()
        .expect("spawn explain");
    assert_ne!(output.status.code(), Some(0));
    let combined = format!(
        "{}
{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("detector") || combined.contains("directory"),
        "explain with file --detectors must fail; got: {combined}"
    );
}
