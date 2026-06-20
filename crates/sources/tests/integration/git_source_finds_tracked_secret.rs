//! GitSource must emit blob content from tracked files.

use crate::support::collect_chunks;
#[cfg(feature = "git")]
#[test]
fn git_source_finds_tracked_secret() {
    use keyhog_sources::GitSource;

    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(
        &repo,
        "secrets.env",
        "GITHUB_TOKEN=ghp_integrationGitSourceTest00000001
",
        "add secret",
    );

    let bodies: Vec<String> = collect_chunks(&GitSource::new(repo).with_max_commits(1))
        .into_iter()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies
            .iter()
            .any(|b| b.contains("ghp_integrationGitSourceTest")),
        "git source must surface blob text; got {bodies:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_source_integration_requires_git() {
    assert!(!cfg!(feature = "git"));
}
