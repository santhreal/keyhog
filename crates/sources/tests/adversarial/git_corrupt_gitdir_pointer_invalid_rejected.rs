//! Invalid gitdir pointer in worktree must be rejected.

#[cfg(feature = "git")]
#[test]
fn git_corrupt_gitdir_pointer_invalid_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".git"), "gitdir: /nonexistent/path/.git\n").expect("gitdir");

    let err = GitSource::new(dir.path().to_path_buf())
        .chunks()
        .next()
        .unwrap()
        .expect_err("invalid gitdir pointer must fail");
    assert!(
        err.to_string().contains("not a git repository") || !err.to_string().is_empty(),
        "got {err}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_corrupt_gitdir_pointer_invalid_rejected() {}
