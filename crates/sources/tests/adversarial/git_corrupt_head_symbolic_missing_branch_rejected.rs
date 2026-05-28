//! Symbolic HEAD pointing at missing branch must error.

#[cfg(feature = "git")]
#[test]
fn git_corrupt_head_symbolic_missing_branch_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;
    let dir = tempfile::tempdir().expect("tempdir");
    let git_dir = dir.path().join(".git");
    std::fs::create_dir_all(git_dir.join("refs/heads")).expect("refs");
    std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/does-not-exist\n").expect("head");

    let err = GitSource::new(dir.path().to_path_buf())
        .chunks()
        .next()
        .unwrap()
        .expect_err("missing branch must fail");
    assert!(!err.to_string().is_empty());
}

#[cfg(not(feature = "git"))]
#[test]
fn git_corrupt_head_symbolic_missing_branch_rejected() {}
