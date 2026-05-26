//! Shared git fixture helpers for one-test-per-file integration gates.

use std::path::{Path, PathBuf};
use std::process::Command;

pub fn init_repo() -> (tempfile::TempDir, PathBuf) {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let repo_path = temp_dir.path().to_path_buf();

    let output = Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(&repo_path)
        .output()
        .expect("git init");
    assert!(output.status.success(), "git init failed: {output:?}");

    Command::new("git")
        .args(["config", "user.email", "a5@test.example"])
        .current_dir(&repo_path)
        .output()
        .expect("git config email");
    Command::new("git")
        .args(["config", "user.name", "LR1 A5"])
        .current_dir(&repo_path)
        .output()
        .expect("git config name");

    (temp_dir, repo_path)
}

pub fn commit(repo: &Path, filename: &str, content: &str, message: &str) {
    std::fs::write(repo.join(filename), content).expect("write fixture");
    Command::new("git")
        .args(["add", filename])
        .current_dir(repo)
        .output()
        .expect("git add");
    let output = Command::new("git")
        .args(["commit", "-m", message])
        .current_dir(repo)
        .output()
        .expect("git commit");
    assert!(output.status.success(), "git commit failed: {output:?}");
}
