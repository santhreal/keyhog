//! Adversarial: watch --detectors pointing at a file must fail.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn watch_detectors_path_is_file_fails() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("not-a-dir.toml");
    std::fs::write(&file, "x = 1\n").unwrap();
    let output = Command::new(binary())
        .args(["watch", "--detectors"])
        .arg(&file)
        .arg(dir.path())
        .output()
        .expect("spawn watch");
    assert_ne!(output.status.code(), Some(0));
    let combined = format!(
        "{}
{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("detector") || combined.contains("watch"),
        "watch with file detectors path must fail; got: {combined}"
    );
}
