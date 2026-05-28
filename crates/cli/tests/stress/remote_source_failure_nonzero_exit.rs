//! KH-GAP-096: When a remote-only scan source fails to read, exit code should not
//! be 0 (CI bots gate on exit status).

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn git_history_on_non_repository_exits_nonzero() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("plain.txt"), "hello\n").expect("write");

    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--git-history"])
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

#[test]
fn github_org_with_invalid_token_exits_nonzero() {
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--fast",
            "--github-org",
            "keyhog-d1-nonexistent-org",
            "--github-token",
            "ghp_invalid_token_for_d1_dogfood",
            ".",
        ])
        .output()
        .expect("spawn");

    assert_ne!(
        output.status.code(),
        Some(0),
        "invalid GitHub PAT must not yield exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
