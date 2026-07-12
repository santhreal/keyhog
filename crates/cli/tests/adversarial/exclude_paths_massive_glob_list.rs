//! Adversarial: repeated `--exclude-paths **/*` patterns must merge without panic.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn exclude_paths_massive_glob_list() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("visible.txt"), "hello\n").unwrap();
    let mut cmd = Command::new(binary());
    cmd.args([
        "scan",
        "--daemon=off",
        "--backend",
        "simd",
        "--format",
        "json",
    ])
    .arg(dir.path());
    for _ in 0..50 {
        cmd.arg("--exclude-paths").arg("**/vendor/**");
    }
    let output = cmd.output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
