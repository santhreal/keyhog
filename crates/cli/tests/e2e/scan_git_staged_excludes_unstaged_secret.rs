//! E2E R5-T-CLI: scan git staged excludes unstaged secret.rs.

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
fn scan_git_staged_excludes_unstaged_secret() {
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
        .args(["commit", "-m", "init", "-q"])
        .current_dir(repo)
        .status()
        .expect("git commit");
    std::fs::write(
        repo.join("secret.env"),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .unwrap();
    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--no-daemon",
            "--git-staged",
            "--format",
            "json",
            "--no-suppress-test-fixtures",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(2));
}
