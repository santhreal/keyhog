//! E2E: the installed git pre-commit hook actually BLOCKS a commit that stages
//! a secret and ALLOWS a clean commit - driven through real `git commit`, not a
//! simulated invocation. This is the whole point of `keyhog hook install`: if
//! the hook exits 0 on a staged secret, every "protected" repo silently ships
//! leaks. We assert the real exit codes and the real commit count.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

fn git(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run git")
}

fn commit_count(dir: &std::path::Path) -> usize {
    let out = git(dir, &["rev-list", "--count", "HEAD"]);
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0)
}

fn install_hook(dir: &std::path::Path) -> std::process::Output {
    Command::new(binary())
        .current_dir(dir)
        .args(["hook", "install"])
        .output()
        .expect("install hook")
}

fn resolved_hooks_dir(dir: &std::path::Path) -> std::path::PathBuf {
    let output = git(
        dir,
        &["rev-parse", "--path-format=absolute", "--git-path", "hooks"],
    );
    assert!(
        output.status.success(),
        "resolve Git hooks path: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::path::PathBuf::from(
        String::from_utf8(output.stdout)
            .expect("UTF-8 hooks path")
            .trim(),
    )
}

fn configure_identity(dir: &std::path::Path) {
    assert!(git(dir, &["config", "user.email", "t@t.t"])
        .status
        .success());
    assert!(git(dir, &["config", "user.name", "t"]).status.success());
}

#[test]
fn hook_blocks_staged_secret_and_allows_clean_commit() {
    let dir = TempDir::new().expect("tempdir");
    let p = dir.path();
    assert!(git(p, &["init", "-q"]).status.success());
    git(p, &["config", "user.email", "t@t.t"]);
    git(p, &["config", "user.name", "t"]);

    // Install the hook via the real subcommand.
    let install = Command::new(binary())
        .current_dir(p)
        .args(["hook", "install"])
        .output()
        .expect("hook install");
    assert!(install.status.success(), "hook install must succeed");
    assert!(
        p.join(".git/hooks/pre-commit").exists(),
        "pre-commit hook file must be written"
    );

    // Put keyhog on PATH so the hook (which calls bare `keyhog`) resolves.
    let bin_dir = binary().parent().unwrap().to_path_buf();
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    // Stage a real secret -> commit MUST be rejected.
    std::fs::write(
        p.join("leak.env"),
        "GH_TOKEN=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\n",
    )
    .unwrap();
    git(p, &["add", "leak.env"]);
    let blocked = Command::new("git")
        .current_dir(p)
        .env("PATH", &path_env)
        .args(["commit", "-m", "should be blocked"])
        .output()
        .expect("git commit");
    assert!(
        !blocked.status.success(),
        "commit staging a secret must be BLOCKED by the hook"
    );
    assert_eq!(
        commit_count(p),
        0,
        "no commit may land with a staged secret"
    );

    // Replace with a clean file -> commit MUST succeed.
    git(p, &["rm", "-q", "--cached", "leak.env"]);
    std::fs::remove_file(p.join("leak.env")).ok();
    std::fs::write(p.join("ok.txt"), "ordinary code, nothing sensitive\n").unwrap();
    git(p, &["add", "ok.txt"]);
    let clean = Command::new("git")
        .current_dir(p)
        .env("PATH", &path_env)
        .args(["commit", "-m", "clean commit"])
        .output()
        .expect("git commit");
    assert!(
        clean.status.success(),
        "a clean commit must be allowed by the hook: {}",
        String::from_utf8_lossy(&clean.stderr)
    );
    assert_eq!(commit_count(p), 1, "the clean commit must land");
}

#[test]
fn hook_install_and_uninstall_follow_core_hooks_path() {
    let dir = TempDir::new().expect("tempdir");
    let p = dir.path();
    assert!(git(p, &["init", "-q"]).status.success());
    assert!(git(p, &["config", "core.hooksPath", ".githooks"])
        .status
        .success());

    let hooks_dir = resolved_hooks_dir(p);
    let installed = install_hook(p);
    assert!(
        installed.status.success(),
        "install at core.hooksPath: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let hook = hooks_dir.join("pre-commit");
    assert!(hook.is_file(), "hook must use Git-resolved path: {hook:?}");
    assert!(
        !p.join(".git/hooks/pre-commit").exists(),
        "hook must not bypass core.hooksPath"
    );

    let removed = Command::new(binary())
        .current_dir(p)
        .args(["hook", "uninstall"])
        .output()
        .expect("uninstall hook");
    assert!(removed.status.success(), "uninstall must succeed");
    assert!(!hook.exists(), "uninstall must use the same resolved path");
}

#[test]
fn hook_install_uses_linked_worktree_hooks_path() {
    let root = TempDir::new().expect("tempdir");
    let primary = root.path().join("primary");
    let linked = root.path().join("linked");
    std::fs::create_dir(&primary).expect("primary dir");
    assert!(git(&primary, &["init", "-q"]).status.success());
    configure_identity(&primary);
    assert!(
        git(&primary, &["commit", "--allow-empty", "-qm", "initial"])
            .status
            .success()
    );
    assert!(git(
        &primary,
        &[
            "worktree",
            "add",
            "-q",
            linked.to_str().expect("linked path")
        ],
    )
    .status
    .success());

    let hooks_dir = resolved_hooks_dir(&linked);
    let installed = install_hook(&linked);
    assert!(
        installed.status.success(),
        "linked-worktree install: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    assert!(hooks_dir.join("pre-commit").is_file());
    assert!(
        !linked.join(".git/hooks/pre-commit").exists(),
        "a linked worktree .git file must never be treated as a hooks directory"
    );
}

#[test]
fn hook_install_uses_bare_repository_hooks_path() {
    let root = TempDir::new().expect("tempdir");
    let bare = root.path().join("repo.git");
    assert!(Command::new("git")
        .args(["init", "--bare", "-q"])
        .arg(&bare)
        .status()
        .expect("init bare repo")
        .success());

    let hooks_dir = resolved_hooks_dir(&bare);
    let installed = install_hook(&bare);
    assert!(
        installed.status.success(),
        "bare-repository install: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    assert!(hooks_dir.join("pre-commit").is_file());
}

#[test]
fn hook_install_uses_submodule_hooks_path() {
    let root = TempDir::new().expect("tempdir");
    let child = root.path().join("child");
    let parent = root.path().join("parent");
    std::fs::create_dir(&child).expect("child dir");
    std::fs::create_dir(&parent).expect("parent dir");
    assert!(git(&child, &["init", "-q"]).status.success());
    configure_identity(&child);
    assert!(git(&child, &["commit", "--allow-empty", "-qm", "initial"])
        .status
        .success());
    assert!(git(&parent, &["init", "-q"]).status.success());
    configure_identity(&parent);
    let add = Command::new("git")
        .current_dir(&parent)
        .args(["-c", "protocol.file.allow=always", "submodule", "add", "-q"])
        .arg(&child)
        .arg("module")
        .output()
        .expect("add submodule");
    assert!(
        add.status.success(),
        "add submodule: {}",
        String::from_utf8_lossy(&add.stderr)
    );
    let module = parent.join("module");

    let hooks_dir = resolved_hooks_dir(&module);
    let installed = install_hook(&module);
    assert!(
        installed.status.success(),
        "submodule install: {}",
        String::from_utf8_lossy(&installed.stderr)
    );
    assert!(hooks_dir.join("pre-commit").is_file());
    assert!(
        !module.join(".git/hooks/pre-commit").exists(),
        "a submodule .git file must never be treated as a hooks directory"
    );
}

/// Locate the directory holding `tool` on the current PATH.
fn dir_of(tool: &str) -> std::path::PathBuf {
    let out = Command::new("sh")
        .args(["-c", &format!("command -v {tool}")])
        .output()
        .expect("locate tool");
    let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
    std::path::Path::new(&path)
        .parent()
        .map(|d| d.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/bin"))
}

#[test]
fn hook_blocks_when_keyhog_not_on_path() {
    // An installed pre-commit hook is a security control. If keyhog is NOT on
    // PATH, the scan did not run and the commit must be blocked with an
    // actionable error instead of silently landing unscanned content.
    let dir = TempDir::new().expect("tempdir");
    let p = dir.path();
    assert!(git(p, &["init", "-q"]).status.success());
    git(p, &["config", "user.email", "t@t.t"]);
    git(p, &["config", "user.name", "t"]);

    let install = Command::new(binary())
        .current_dir(p)
        .args(["hook", "install"])
        .output()
        .expect("hook install");
    assert!(install.status.success(), "hook install must succeed");

    // Minimal PATH that has git but deliberately NOT keyhog (keyhog lives in
    // the cargo target dir, never in a standard bin dir).
    let minimal_path = format!("{}:/usr/bin:/bin", dir_of("git").display());
    // Sanity: keyhog must be unresolvable under this PATH, or the test proves
    // nothing.
    let resolvable = Command::new("sh")
        .args(["-c", "command -v keyhog"])
        .env("PATH", &minimal_path)
        .output()
        .expect("probe keyhog")
        .status
        .success();
    assert!(
        !resolvable,
        "test setup error: keyhog resolved under the supposedly-minimal PATH"
    );

    // Even with a real staged secret, this test is primarily proving the
    // missing-binary contract: the hook must block before it can claim coverage.
    std::fs::write(
        p.join("leak.env"),
        "GH_TOKEN=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\n",
    )
    .unwrap();
    git(p, &["add", "leak.env"]);
    let out = Command::new("git")
        .current_dir(p)
        .env("PATH", &minimal_path)
        .args(["commit", "-m", "keyhog absent"])
        .output()
        .expect("git commit");
    assert!(
        !out.status.success(),
        "commit must be blocked when keyhog is not on PATH; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        commit_count(p),
        0,
        "the commit must not land when the scanner is absent"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found on PATH") && stderr.contains("blocking commit"),
        "the hook must explain why it blocked; stderr: {stderr}"
    );
    assert!(
        stderr.contains("fix PATH"),
        "the hook must explain how to repair the missing binary; stderr: {stderr}"
    );
}
