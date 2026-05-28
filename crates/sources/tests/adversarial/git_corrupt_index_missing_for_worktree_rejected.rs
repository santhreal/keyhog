//! Worktree missing index with dangling HEAD must not panic.

#[cfg(feature = "git")]
#[test]
fn git_corrupt_index_missing_for_worktree_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(git_dir.join("refs/heads")).expect("refs");
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").expect("head");
    std::fs::write(git_dir.join("refs/heads/main"), "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n").expect("ref");
    std::fs::write(dir.path().join("tracked.txt"), "x\n").expect("tracked");

    let err = GitSource::new(dir.path().to_path_buf())
        .chunks()
        .next()
        .unwrap()
        .expect_err("missing git objects must fail");
    assert!(!err.to_string().is_empty());
}

#[cfg(not(feature = "git"))]
#[test]
fn git_corrupt_index_missing_for_worktree_rejected() {}
