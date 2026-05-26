//! GitHistorySource must surface added lines from commit patches.

#[cfg(feature = "git")]
#[test]
fn git_history_finds_added_line() {
    use keyhog_core::Source;
    use keyhog_sources::GitHistorySource;

    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(&repo, "a.txt", "old=1
", "init");
    crate::support::git::commit(
        &repo,
        "a.txt",
        "old=1
NEW_TOKEN=ghp_historyLineAdded00000001
",
        "add line",
    );

    let bodies: Vec<String> = GitHistorySource::new(repo)
        .with_max_commits(5)
        .chunks()
        .flatten()
        .map(|c| c.data.to_string())
        .collect();
    assert!(
        bodies.iter().any(|b| b.contains("ghp_historyLineAdded")),
        "history source must include added lines; got {bodies:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_history_integration_requires_git() {
    assert!(!cfg!(feature = "git"));
}
