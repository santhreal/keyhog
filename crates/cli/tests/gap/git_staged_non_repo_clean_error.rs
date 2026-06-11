//! DF-03 guard: `--git-staged` outside a git repository must fail with a CLEAN,
//! actionable message — not a raw git error leak, and never a false all-clear.
//!
//! Dogfood hit `keyhog scan --git-staged` outside a repo and got a raw
//! `git diff failed: error: ...` leaked straight from the diff invocation. The
//! fix probes `git rev-parse --is-inside-work-tree` first and bails with an
//! operator-facing explanation. This guard pins three things: (1) non-zero exit
//! (a CI gate must see failure), (2) no "clean" summary (the staged scan never
//! ran, so it must not read as all-clear), (3) the actionable hint naming
//! `--git-staged` and the not-a-repo cause.

use crate::e2e::support::binary;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn git_staged_outside_repo_fails_cleanly_with_actionable_message() {
    let dir = TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("plain.txt"), "hello\n").expect("write");

    let output = Command::new(binary())
        .args(["scan", "--no-daemon", "--git-staged"])
        .arg(dir.path())
        .output()
        .expect("spawn");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");

    assert_ne!(
        output.status.code(),
        Some(0),
        "git-staged outside a repo must not exit 0; stdout={stdout} stderr={stderr}"
    );
    assert!(
        !combined.contains("Your code is clean"),
        "a failed staged scan must not print the clean-repo summary; combined={combined}"
    );

    // Clean, actionable message — names the cause and the offending flag.
    assert!(
        combined.contains("not a git repository"),
        "error must explain the not-a-repo cause; combined={combined}"
    );
    assert!(
        combined.contains("--git-staged"),
        "error must name the flag whose precondition failed; combined={combined}"
    );

    // The raw git diff error must NOT leak through (that was the bug).
    assert!(
        !combined.contains("git diff failed"),
        "the raw `git diff failed: ...` leak must be replaced by the clean message; \
         combined={combined}"
    );
}
