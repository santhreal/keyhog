//! R3-D / KH-GAP-092: `--git-diff HEAD` JSON finding shape on worktree secret.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn scan_git_diff_head_worktree_json_shape() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    for (args, msg) in [
        (vec!["init", "-q"], "git init"),
        (vec!["config", "user.email", "r3d@test"], "email"),
        (vec!["config", "user.name", "R3D"], "name"),
    ] {
        std::process::Command::new("git")
            .args(&args)
            .current_dir(repo)
            .status()
            .expect(msg);
    }
    std::fs::write(repo.join("base.txt"), "x\n").unwrap();
    std::process::Command::new("git")
        .args(["add", "base.txt"])
        .current_dir(repo)
        .status()
        .unwrap();
    std::process::Command::new("git")
        .args(["commit", "-m", "base", "-q"])
        .current_dir(repo)
        .status()
        .unwrap();
    std::fs::write(
        repo.join("leak.env"),
        "export AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .unwrap();

    let output = Command::new(binary())
        .args([
            "scan",
            "--no-daemon",
            "--git-diff",
            "HEAD",
            "--format",
            "json",
            "--backend",
            "simd",
            "--no-suppress-test-fixtures",
        ])
        .current_dir(repo)
        .output()
        .expect("spawn");

    assert_eq!(output.status.code(), Some(1));
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&output.stdout)).expect("json array");
    let obj = &v[0];
    // Law 6: pin the actual attribution, not just that the keys exist. The
    // planted `AKIAKPQXRMSNTBVWYZBN` in the worktree file must surface as the
    // aws-access-key detector, pointing at leak.env.
    assert_eq!(
        obj.get("detector_id").and_then(|d| d.as_str()),
        Some("aws-access-key"),
        "git-diff HEAD worktree scan must attribute the planted AKIA key to aws-access-key; got {v}"
    );
    assert_eq!(
        obj.get("severity").and_then(|s| s.as_str()),
        Some("critical"),
        "aws-access-key must carry its critical severity value, not just any string; got {v}"
    );
    assert!(
        obj["location"]["file_path"]
            .as_str()
            .unwrap_or_default()
            .contains("leak.env"),
        "finding must point at the worktree file leak.env; got {v}"
    );
}
