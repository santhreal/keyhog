//! GitSource chunks must include file path metadata.

use crate::support::collect_chunks;
#[cfg(feature = "git")]
#[test]
fn git_source_chunk_has_path_metadata() {
    use keyhog_sources::GitSource;

    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(
        &repo,
        "tracked.env",
        "X=1
",
        "init",
    );

    let paths: Vec<String> = collect_chunks(&GitSource::new(repo).with_max_commits(1))
        .into_iter()
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
