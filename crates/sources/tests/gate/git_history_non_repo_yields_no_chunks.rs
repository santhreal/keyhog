//! LR1-A8 replacement gate: `git/history.rs` non-repo yields no chunks.

#[cfg(feature = "git")]
use keyhog_core::Source;
#[cfg(feature = "git")]
use keyhog_sources::GitHistorySource;

#[cfg(feature = "git")]
#[test]
fn git_history_on_non_repo_yields_error_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let source = GitHistorySource::new(dir.path().to_path_buf());
    assert_eq!(source.name(), "git-history");
    let first = source.chunks().next();
    assert!(
        first.is_some(),
        "non-repo must yield at least one iterator item"
    );
    assert!(
        first.unwrap().is_err(),
        "non-repo git-history must surface SourceError"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_history_gate_skipped_without_feature() {}
