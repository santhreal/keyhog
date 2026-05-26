//! LR1-A8 replacement gate: `git/diff.rs` invalid ref on non-repo.

#[cfg(feature = "git")]
use keyhog_core::Source;
#[cfg(feature = "git")]
use keyhog_sources::GitDiffSource;

#[cfg(feature = "git")]
#[test]
fn git_diff_on_non_repo_yields_error_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let source = GitDiffSource::new(dir.path().to_path_buf(), "main");
    assert_eq!(source.name(), "git-diff");
    let first = source.chunks().next();
    assert!(
        first.is_some(),
        "non-repo must yield at least one iterator item"
    );
    assert!(
        first.unwrap().is_err(),
        "non-repo git-diff must surface SourceError"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_diff_gate_skipped_without_feature() {}
