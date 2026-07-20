//! KH-GAP-096 (git-diff variant): `--git-diff` against a non-repository must
//! not exit 0 / report "clean", the requested diff scan never ran, so a CI
//! gate must see a failure, not a false all-clear.

use crate::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn git_diff_on_non_repository_exits_nonzero_without_clean_summary() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("plain.txt"), "hello\n").expect("write");

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--git-diff",
            "HEAD",
            "--git-diff-path",
        ])
        .arg(dir.path())
        .output()
        .expect("spawn");

    assert_ne!(
        output.status.code(),
        Some(0),
        "git-diff on a non-repo must not exit 0; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("Your code is clean"),
        "source failure must not print the clean-repo summary; combined={combined}"
    );
}
