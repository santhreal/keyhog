//! Non-repository directories must be refused by validate_repo_path.

#[cfg(feature = "git")]
#[test]
fn git_non_repo_path_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("plain.txt"),
        "not a repo
",
    )
    .expect("write");

    let source = GitSource::new(dir.path().to_path_buf());
    let err = source
        .chunks()
        .next()
        .unwrap()
        .expect_err("non-repo must fail");
    assert!(
        err.to_string().contains("not a git repository"),
        "got {err}"
    );
}
