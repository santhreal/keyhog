//! E2E R5-T-CLI: scan exclude paths with git staged.rs.

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
fn scan_exclude_paths_with_git_staged() {
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
    std::process::Command::new("git")
        .args(["add", "secret.env"])
        .current_dir(repo)
        .status()
        .expect("git add");
    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--git-staged",
            "--format",
            "json",
            "--exclude-paths",
            "secret.env",
            "--no-suppress-test-fixtures",
        ])
        .current_dir(repo)
        .arg(".")
        .output()
        .expect("spawn");
    assert_eq!(output.status.code(), Some(0));
    let findings: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("json");
    assert!(findings.as_array().unwrap().is_empty());
}
