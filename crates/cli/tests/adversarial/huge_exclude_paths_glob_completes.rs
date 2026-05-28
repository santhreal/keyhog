//! Adversarial: hundreds of `--exclude-paths` globs must not hang or panic.

use crate::adversarial::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn huge_exclude_paths_glob_completes() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("keep.txt"), "hello\n").unwrap();
    let mut cmd = Command::new(binary());
    cmd.arg("scan").args(["--no-daemon", "--format", "json"]).arg(dir.path());
    for i in 0..200 {
        cmd.arg("--exclude-paths").arg(format!("**/noise{i}.txt"));
    }
    let output = cmd.output().expect("spawn");
    assert_eq!(output.status.code(), Some(0), "stderr={}", String::from_utf8_lossy(&output.stderr));
}
