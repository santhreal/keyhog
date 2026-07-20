//! R5-D2 / KH-GAP-167: `--git-staged` must scan the index, not the worktree only.

use crate::support::binary;
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
    std::fs::write(repo.join("staged.env"), "clean working tree replacement\n").unwrap();

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
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
        "the exact staged index blob must be scanned even after the working-tree file changes; stdout={stdout}"
    );
}

#[test]
fn git_staged_from_nested_directory_uses_the_enclosing_index() {
    let dir = TempDir::new().expect("tempdir");
    let repo = dir.path();
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(repo)
        .status()
        .expect("git init");
    std::fs::create_dir_all(repo.join("src/nested")).expect("create nested directory");
    std::fs::write(
        repo.join("staged.env"),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .expect("write staged secret");
    assert!(Command::new("git")
        .args(["add", "staged.env"])
        .current_dir(repo)
        .status()
        .expect("git add")
        .success());

    let output = Command::new(binary())
        .args([
            "scan",
            "--daemon=off",
            "--git-staged",
            "--format",
            "json",
            "--backend",
            "simd",
            "--no-suppress-test-fixtures",
        ])
        .current_dir(repo.join("src/nested"))
        .output()
        .expect("spawn nested staged scan");

    assert_eq!(
        output.status.code(),
        Some(1),
        "nested staged scan must find the enclosing index secret; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let findings: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("nested staged scan stdout must be a JSON array");
    assert_eq!(findings.as_array().map(Vec::len), Some(1));
    assert_eq!(
        findings[0]["location"]["file_path"],
        serde_json::Value::String("staged.env".into()),
        "staged paths must remain relative to the enclosing worktree root"
    );
}
