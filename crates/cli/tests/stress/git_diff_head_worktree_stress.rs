//! R5-D2 / KH-GAP-168: `--git-diff HEAD` must include uncommitted worktree changes.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn git_diff_head_worktree_secret_exit_one() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(repo)
        .status()
        .expect("git init");
    std::process::Command::new("git")
        .args(["config", "user.email", "r5d2@test"])
        .current_dir(repo)
        .status()
        .expect("git config email");
    std::process::Command::new("git")
        .args(["config", "user.name", "R5D2"])
        .current_dir(repo)
        .status()
        .expect("git config name");

    std::fs::write(repo.join("clean.txt"), "ok\n").unwrap();
    std::process::Command::new("git")
        .args(["add", "clean.txt"])
        .current_dir(repo)
        .status()
        .expect("git add");
    std::process::Command::new("git")
        .args(["commit", "-m", "init", "-q"])
        .current_dir(repo)
        .status()
        .expect("git commit");

    std::fs::write(
        repo.join("worktree.env"),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--git-diff",
            "HEAD",
            "--format",
            "json",
            // Deterministic CPU-SIMD backend (e2e convention): this verifies
            // git-diff recall, not autoroute; un-calibrated `auto` fails closed.
            "--backend",
            "simd",
            "--no-suppress-test-fixtures",
        ])
        .current_dir(repo)
        .output()
        .expect("spawn");

    assert_eq!(
        output.status.code(),
        Some(1),
        "git-diff HEAD must find worktree secret; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
