//! R3-D / KH-GAP-092: `--git-diff HEAD` must include uncommitted worktree
//! changes (tracked diffs and untracked files), unlike the old HEAD..HEAD
//! commit-range-only behavior.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn scan_git_diff_head_includes_uncommitted_worktree_changes() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(repo)
        .status()
        .expect("git init");
    std::process::Command::new("git")
        .args(["config", "user.email", "d2@test"])
        .current_dir(repo)
        .status()
        .expect("git config email");
    std::process::Command::new("git")
        .args(["config", "user.name", "D2"])
        .current_dir(repo)
        .status()
        .expect("git config name");

    std::fs::write(repo.join("clean.txt"), "ok\n").unwrap();
    std::fs::write(repo.join("secret.env"), "SAFE=1\n").unwrap();
    std::process::Command::new("git")
        .args(["add", "clean.txt", "secret.env"])
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
            "--daemon=off",
            "--git-diff",
            "HEAD",
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
        "git-diff HEAD must find uncommitted secret; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be valid JSON array");
    let arr = findings.as_array().expect("json array");
    assert_eq!(arr.len(), 1, "expected exactly one finding; got {stdout}");
    assert_eq!(
        arr[0]["detector_id"].as_str(),
        Some("aws-access-key"),
        "unexpected detector in {stdout}"
    );
    assert!(
        arr[0]["location"]["file_path"]
            .as_str()
            .is_some_and(|p| p.ends_with("secret.env")),
        "finding must cite secret.env; got {stdout}"
    );
}
