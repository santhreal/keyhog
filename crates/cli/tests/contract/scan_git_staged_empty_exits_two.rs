//! Contract: `--git-staged` with empty index exits 2.

#[cfg(feature = "git")]
#[test]
fn scan_git_staged_empty_exits_two() {
    use crate::e2e::support::binary;
    use std::process::Command;
    use tempfile::TempDir;

    let dir = TempDir::new().expect("tempdir");
    std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .status()
        .expect("git init");
    std::fs::write(dir.path().join("tracked.txt"), "hello\n").expect("write");
    // Index intentionally empty (file exists but is not staged).

    let output = Command::new(binary())
        .args(["scan", "--daemon=off", "--git-staged", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .expect("spawn");

    assert_eq!(
        output.status.code(),
        Some(2),
        "empty staged set must exit 2; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn scan_git_staged_empty_exits_two() {
    // Git feature disabled in this build (runtime contract covered in git-enabled CI).
}
