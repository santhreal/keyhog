//! R5-T git adversarial: history with max_commits=1 yields one commit worth.

use crate::support::split_chunk_results;
#[cfg(feature = "git")]
#[test]
fn r5t_git_history_max_commits_one_stops() {
    use keyhog_core::Source;
    use keyhog_sources::GitHistorySource;
    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(&repo, "a.txt", "a=1\n", "one");
    crate::support::git::commit(&repo, "b.txt", "b=2\n", "two");
    let source = GitHistorySource::new(repo).with_max_commits(1);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "max_commits=1 git history scan should not emit SourceError rows: {errors:?}"
    );
    let bodies: String = chunks.iter().map(|c| c.data.to_string()).collect();
    assert!(
        bodies.contains("b=2"),
        "max_commits=1 must include only latest commit; got {bodies}"
    );
    assert!(
        !bodies.contains("a=1"),
        "older commit must be skipped; got {bodies}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.contains("b.txt"))),
        "latest commit chunk must carry path metadata; chunks={chunks:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn r5t_git_history_max_commits_one_stops() {}
