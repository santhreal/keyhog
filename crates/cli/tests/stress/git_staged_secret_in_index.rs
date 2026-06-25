//! R5-D2 / KH-GAP-167: `--git-staged` must scan the index, not the worktree only.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn git_staged_secret_in_index_exit_one() {
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
        repo.join("staged.env"),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .unwrap();
    std::process::Command::new("git")
        .args(["add", "staged.env"])
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
            // Deterministic CPU-SIMD backend (e2e convention): this verifies
            // staged-index recall, not autoroute; un-calibrated `auto` fails closed.
            "--backend",
            "simd",
            "--no-suppress-test-fixtures",
        ])
        .current_dir(repo)
        .output()
        .expect("spawn");

    assert_eq!(
        output.status.code(),
        Some(1),
        "staged secret must exit 1; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let findings: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be JSON array");
    assert_eq!(
        findings.as_array().map(|a| a.len()),
        Some(1),
        "expected one staged finding; stdout={stdout}"
    );
}
