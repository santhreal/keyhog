//! GitDiffSource plugin name contract.

#[cfg(feature = "git")]
#[test]
fn git_diff_source_name() {
    use keyhog_core::Source;
    use keyhog_sources::GitDiffSource;
    let source = GitDiffSource::new(std::path::PathBuf::from("."), "main");
    assert_eq!(source.name(), "git-diff");
}

#[cfg(not(feature = "git"))]
#[test]
fn git_diff_name_requires_git() {
    assert!(!cfg!(feature = "git"));
}
