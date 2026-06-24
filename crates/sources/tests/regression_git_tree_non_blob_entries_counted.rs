#![cfg(feature = "git")]

mod support;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{git_object_unreadable, GitSource};
use std::path::Path;
use std::process::Command;
use support::split_chunk_results;

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|error| panic!("git {args:?} failed to spawn: {error}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_repo(repo: &Path) {
    git(repo, &["init", "-b", "main"]);
    git(repo, &["config", "user.email", "gitlink@test.example"]);
    git(repo, &["config", "user.name", "Gitlink Regression"]);
}

#[test]
fn gitlink_tree_entry_is_counted_as_unscanned_coverage_gap() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let before = git_object_unreadable();

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    init_repo(repo);

    std::fs::write(repo.join("safe.env"), "SAFE_GITLINK_SIBLING=visible\n").expect("write safe");
    git(repo, &["add", "safe.env"]);
    git(
        repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            "160000,0000000000000000000000000000000000000001,deps/submodule",
        ],
    );
    git(repo, &["commit", "-m", "add safe sibling and gitlink"]);

    let rows: Vec<_> = GitSource::new(repo.to_path_buf()).chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<_> = chunks.iter().map(|chunk| chunk.data.to_string()).collect();

    assert_eq!(
        errors.len(),
        1,
        "gitlink coverage accounting must emit one SourceError row without aborting safe sibling scans"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("deps/submodule")
            && error.contains("unsupported mode")
            && error.contains("referenced content was not scanned"),
        "gitlink SourceError must name the unscanned tree entry, got {error}"
    );
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("SAFE_GITLINK_SIBLING")),
        "safe sibling blob must still scan when a gitlink is present; bodies={bodies:?}"
    );

    let after = git_object_unreadable();
    assert_eq!(
        after - before,
        1,
        "gitlink tree entries reference content outside this repository object database and must be counted as unscanned coverage"
    );
}
