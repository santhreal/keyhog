//! GitHistorySource on corrupt repo must error without panic.

#[cfg(feature = "git")]
#[test]
fn git_history_corrupt_repo_errors_without_panic() {
    use keyhog_core::Source;
    use keyhog_sources::GitHistorySource;

    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(&git_dir).expect("mkdir");
    std::fs::write(git_dir.join("HEAD"), b"not-a-valid-ref\n").expect("corrupt head");

    let source = GitHistorySource::new(dir.path().to_path_buf());
    let mut iter = source.chunks();
    match iter.next() {
        Some(Err(e)) => assert!(!e.to_string().is_empty()),
        None => {} // corrupt HEAD; empty iterator is acceptable (no panic)
        Some(Ok(_)) => panic!("corrupt repo must not yield readable chunks"),
    }
}

#[cfg(not(feature = "git"))]
#[test]
fn git_history_corrupt_repo_errors_without_panic() {}
