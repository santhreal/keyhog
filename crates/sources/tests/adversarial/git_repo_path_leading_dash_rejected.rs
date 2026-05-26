//! Repository paths starting with - must be rejected before git invocation.

#[cfg(feature = "git")]
#[test]
fn git_repo_path_leading_dash_rejected() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;

    let source = GitSource::new(std::path::PathBuf::from("-etc-passwd"));
    let err = source.chunks().next().unwrap().expect_err("dash repo path");
    assert!(
        err.to_string().contains("unsafe characters")
            || err.to_string().contains("not a git repository"),
        "got {err}"
    );
}
