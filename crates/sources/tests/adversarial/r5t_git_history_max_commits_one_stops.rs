//! R5-T git adversarial: history with max_commits=1 yields one commit worth.

#[cfg(feature = "git")]
#[test]
fn r5t_git_history_max_commits_one_stops() {
    use keyhog_core::Source;
    use keyhog_sources::GitHistorySource;
    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(&repo, "a.txt", "a=1\n", "one");
    crate::support::git::commit(&repo, "b.txt", "b=2\n", "two");
    let chunks: Vec<_> = GitHistorySource::new(repo)
        .with_max_commits(1)
        .chunks()
        .flatten()
        .collect();
    let bodies: String = chunks.iter().map(|c| c.data.to_string()).collect();
    assert!(
        bodies.contains("b=2"),
        "max_commits=1 must include only latest commit; got {bodies}"
    );
    assert!(
        !bodies.contains("a=1"),
        "older commit must be skipped; got {bodies}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn r5t_git_history_max_commits_one_stops() {}
