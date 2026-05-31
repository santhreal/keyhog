//! E2E R5-T-CLI: scan git history max commits one clean top.rs.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

fn init_git_repo(dir: &std::path::Path) {
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir)
        .status()
        .expect("git init");
    std::process::Command::new("git")
        .args(["config", "user.email", "r5-cli@test"])
        .current_dir(dir)
        .status()
        .expect("git config email");
    std::process::Command::new("git")
        .args(["config", "user.name", "R5 CLI"])
        .current_dir(dir)
        .status()
        .expect("git config name");
}

#[test]
fn scan_git_history_max_commits_one_clean_top() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("clean.txt"), "ok\n").unwrap();
    std::process::Command::new("git")
        .args(["add", "clean.txt"])
        .current_dir(repo)
        .status()
        .expect("git add");
    std::process::Command::new("git")
        .args(["commit", "-m", "only", "-q"])
        .current_dir(repo)
        .status()
        .expect("git commit");
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--git-history",
            ".",
            "--max-commits",
            "1",
            "--format",
            "json",
        ])
        .current_dir(repo)
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
