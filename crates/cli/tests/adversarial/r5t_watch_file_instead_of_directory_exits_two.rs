//! R5-T adversarial non-scan: watch on plain file exits 2.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn r5t_watch_file_instead_of_directory_exits_two() {
    let dir = TempDir::new().expect("tempdir");
    let file = dir.path().join("not-a-dir.txt");
    std::fs::write(&file, "x\n").unwrap();
    let output = Command::new(binary())
        .args(["watch"])
        .arg(&file)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
}
