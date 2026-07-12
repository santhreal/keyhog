//! KH-GAP-096: Remote/git-only scan sources must not exit 0 when the source fails.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn git_history_on_non_repository_exits_nonzero() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("plain.txt"), "hello\n").expect("write");

    let output = Command::new(binary())
        .args(["scan", "--daemon=off", "--git-history"])
        .arg(dir.path())
        .output()
        .expect("spawn");

    assert_ne!(
        output.status.code(),
        Some(0),
        "git-history on a non-repo must not exit 0; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
