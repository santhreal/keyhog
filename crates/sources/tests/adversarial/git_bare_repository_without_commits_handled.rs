//! Bare repo with no commits must not panic.

#[cfg(feature = "git")]
#[test]
fn git_bare_repository_without_commits_handled() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join("repo.git");
    std::fs::create_dir_all(&git_dir).expect("mkdir");
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").expect("head");
    std::fs::create_dir_all(git_dir.join("refs/heads")).expect("refs");

    let chunks: Vec<_> = GitSource::new(git_dir).chunks().collect();
    assert!(
        chunks.is_empty() || chunks.iter().all(Result::is_err),
        "bare repo without commits must not panic; got {chunks:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_bare_repository_without_commits_handled() {}
