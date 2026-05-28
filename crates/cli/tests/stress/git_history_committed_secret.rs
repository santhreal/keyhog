//! R5-D2 / KH-GAP-169: `--git-history` must surface secrets from prior commits.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn git_history_committed_secret_exit_one() {
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

    std::fs::write(
        repo.join("history.env"),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .unwrap();
    std::process::Command::new("git")
        .args(["add", "history.env"])
        .current_dir(repo)
        .status()
        .expect("git add");
    std::process::Command::new("git")
        .args(["commit", "-m", "plant", "-q"])
        .current_dir(repo)
        .status()
        .expect("git commit");
    std::fs::write(repo.join("history.env"), "clean\n").unwrap();

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--git-history",
            ".",
            "--format",
            "json",
            "--no-suppress-test-fixtures",
        ])
        .current_dir(repo)
        .output()
        .expect("spawn");

    assert_eq!(
        output.status.code(),
        Some(1),
        "git-history must find committed secret; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("history.env"),
        "finding must cite history.env; stdout={stdout}"
    );
}
