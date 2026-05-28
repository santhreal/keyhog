//! E2E R5-T-CLI: scan git diff path override outside cwd.rs.

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
fn scan_git_diff_path_override_outside_cwd() {
    let outer = TempDir::new().expect("tempdir");
    let repo = outer.path().join("repo");
    std::fs::create_dir(&repo).unwrap();
    init_git_repo(&repo);
    std::fs::write(repo.join("clean.txt"), "ok\n").unwrap();
    std::process::Command::new("git").args(["add", "clean.txt"]).current_dir(&repo).status().expect("git add");
    std::process::Command::new("git").args(["commit", "-m", "init", "-q"]).current_dir(&repo).status().expect("git commit");
    std::fs::write(repo.join("secret.env"), "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n").unwrap();
    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--git-diff", "HEAD", "--git-diff-path"])
        .arg(&repo)
        .args(["--format", "json", "--no-suppress-test-fixtures"])
        .current_dir(outer.path()).output().expect("spawn");
    assert_eq!(output.status.code(), Some(1));
    let findings: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("json");
    assert_eq!(findings.as_array().unwrap().len(), 1);
}
