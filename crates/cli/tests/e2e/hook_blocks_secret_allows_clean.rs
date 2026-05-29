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
        "GH_TOKEN=ghp_aB3xK9mZ1qW7rT5vY2nL8pH4jD6sF0gE1cV2\n",
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
fn hook_fails_open_when_keyhog_not_on_path() {
    // A pre-commit secret scan is best-effort (CI is the real gate). When
    // keyhog is NOT on PATH the hook must SKIP the scan with a clear message,
    // not block the commit. The old template was a bare `keyhog scan ...`,
    // which makes `sh` exit 127 ("keyhog: not found"); git treats any nonzero
    // hook exit as failure, so EVERY commit - including clean ones - was
    // bricked with a cryptic error in any environment without keyhog on PATH
    // (a fresh shell, CI, or a contributor who never installed it). The fixed
    // hook guards with `command -v keyhog` and exits 0 with guidance.
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

    // Even a staged real secret must NOT block the commit when keyhog is
    // absent: the scan is skipped, not failed.
    std::fs::write(
        p.join("leak.env"),
        "GH_TOKEN=ghp_aB3xK9mZ1qW7rT5vY2nL8pH4jD6sF0gE1cV2\n",
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
        out.status.success(),
        "commit must succeed (fail-open) when keyhog is not on PATH; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        commit_count(p),
        1,
        "the commit must land when the scanner is absent (no bricking)"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found on PATH"),
        "the hook must explain why it skipped the scan; stderr: {stderr}"
    );
}
