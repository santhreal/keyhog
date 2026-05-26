//! GitHistorySource plugin name contract.

#[cfg(feature = "git")]
#[test]
fn git_history_source_name() {
    use keyhog_core::Source;
    use keyhog_sources::GitHistorySource;
    let source = GitHistorySource::new(std::path::PathBuf::from("."));
    assert_eq!(source.name(), "git-history");
}

#[cfg(not(feature = "git"))]
#[test]
fn git_history_name_requires_git() {
    assert!(!cfg!(feature = "git"));
}
