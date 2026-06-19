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
    assert!(obj.get("detector_id").is_some());
    assert!(obj.get("severity").is_some());
    assert!(obj["location"].get("file_path").is_some());
}
