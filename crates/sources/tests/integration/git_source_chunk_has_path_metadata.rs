//! GitSource chunks must include file path metadata.

#[cfg(feature = "git")]
#[test]
fn git_source_chunk_has_path_metadata() {
    use keyhog_core::Source;
    use keyhog_sources::GitSource;

    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(
        &repo,
        "tracked.env",
        "X=1
",
        "init",
    );

    let paths: Vec<String> = GitSource::new(repo)
        .with_max_commits(1)
        .chunks()
        .flatten()
        .filter_map(|c| c.metadata.path.clone())
        .collect();
    assert!(
        paths.iter().any(|p| p.contains("tracked.env")),
        "git chunk must carry blob path; got {paths:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_chunk_path_requires_git() {
    assert!(!cfg!(feature = "git"));
}
