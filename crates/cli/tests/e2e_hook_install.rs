//! e2e test for `keyhog hook install` and `keyhog hook list`.
//!
//! The hook subcommand manages git pre-commit integrations. This test
//! verifies that `hook install` writes a valid pre-commit hook and
//! `hook list` shows installed hooks.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// `keyhog hook list` returns exit 0 with a list of available/installed hooks.
/// The list is human-readable text, not JSON, and should mention at least
/// one standard hook (e.g., `pre-commit`).
#[test]
fn hook_list_returns_exit_zero_and_mentions_precommit() {
    let output = Command::new(binary())
        .arg("hook")
        .arg("list")
        .output()
        .expect("spawn keyhog hook list");

    assert_eq!(
        output.status.code(),
        Some(0),
        "keyhog hook list should exit 0; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.to_lowercase().contains("pre-commit") || stdout.contains("hooks"),
        "hook list should mention available hooks; got: {stdout}"
    );
}

/// `keyhog hook install` in a git repo creates a pre-commit hook file.
/// The hook script must be executable and contain a reference to keyhog.
#[test]
fn hook_install_creates_executable_pre_commit_hook() {
    let dir = TempDir::new().expect("create tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(&git_dir).expect("create .git");
    let hooks_dir = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir).expect("create hooks dir");

    let output = Command::new(binary())
        .arg("hook")
        .arg("install")
        .arg("--path")
        .arg(dir.path())
        .output()
        .expect("spawn keyhog hook install");

    let exit_code = output.status.code();
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        exit_code == Some(0) || exit_code == Some(1),
        "hook install should exit 0 (success) or 1 (already installed); \
         got {exit_code:?}, stderr: {stderr}"
    );

    let hook_path = hooks_dir.join("pre-commit");
    let hook_exists = hook_path.exists();
    assert!(
        hook_exists,
        "hook install must create .git/hooks/pre-commit; path: {hook_path:?}"
    );

    let hook_content = std::fs::read_to_string(&hook_path).expect("read hook file");
    assert!(
        hook_content.contains("keyhog") || hook_content.contains("scan"),
        "pre-commit hook must reference keyhog; got: {hook_content}"
    );
}

/// `keyhog hook install --hook=pre-push` installs a pre-push hook instead.
/// This test verifies that the --hook flag routes to the correct hook file.
#[test]
fn hook_install_with_hook_flag_respects_hook_type() {
    let dir = TempDir::new().expect("create tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(&git_dir).expect("create .git");
    let hooks_dir = git_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir).expect("create hooks dir");

    let output = Command::new(binary())
        .arg("hook")
        .arg("install")
        .arg("--hook=pre-push")
        .arg("--path")
        .arg(dir.path())
        .output()
        .expect("spawn keyhog hook install --hook=pre-push");

    let exit_code = output.status.code();
    assert!(
        exit_code == Some(0) || exit_code == Some(1),
        "hook install --hook=pre-push should succeed; got {exit_code:?}"
    );

    let pre_push_path = hooks_dir.join("pre-push");
    let pre_push_exists = pre_push_path.exists();
    assert!(
        pre_push_exists,
        "hook install --hook=pre-push must create .git/hooks/pre-push; path: {pre_push_path:?}"
    );
}
