//! E2E R5-T-CLI: scan max commits limits git history.rs.

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
fn scan_max_commits_limits_git_history() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    init_git_repo(repo);
    std::fs::write(repo.join("old.env"), "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n").unwrap();
    std::process::Command::new("git").args(["add", "old.env"]).current_dir(repo).status().expect("git add");
    std::process::Command::new("git").args(["commit", "-m", "old leak", "-q"]).current_dir(repo).status().expect("git commit");
    std::fs::write(repo.join("clean.txt"), "ok\n").unwrap();
    std::process::Command::new("git").args(["add", "clean.txt"]).current_dir(repo).status().expect("git add");
    std::process::Command::new("git").args(["commit", "-m", "clean", "-q"]).current_dir(repo).status().expect("git commit");
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--git-history", "--format", "json", "--max-commits", "1", "--no-suppress-test-fixtures"])
        .current_dir(repo).arg(".").output().expect("spawn");
    assert_eq!(output.status.code(), Some(0));
}
