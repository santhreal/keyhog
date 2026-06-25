//! GitHistorySource must surface added lines from commit patches.

#[cfg(feature = "git")]
use crate::support::split_chunk_results;
#[cfg(feature = "git")]
use keyhog_core::Source;

#[cfg(feature = "git")]
#[test]
fn git_history_finds_added_line() {
    use keyhog_sources::GitHistorySource;

    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(
        &repo, "a.txt", "old=1
", "init",
    );
    crate::support::git::commit(
        &repo,
        "a.txt",
        "old=1
NEW_TOKEN=ghp_historyLineAdded00000001
",
        "add line",
    );

    let source = GitHistorySource::new(repo).with_max_commits(5);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid GitHistorySource fixture must not emit SourceError rows, got {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        2,
        "two commits with added lines should emit two history chunks, got {chunks:?}"
    );
    let bodies: Vec<String> = chunks.iter().map(|c| c.data.to_string()).collect();
    let secret_chunk = chunks
        .iter()
        .copied()
        .find(|chunk| chunk.data.contains("ghp_historyLineAdded"))
        .expect("history source must include added secret line");
    assert_eq!(secret_chunk.metadata.source_type, "git-history");
    assert_eq!(
        secret_chunk.metadata.author.as_deref(),
        Some("LR1 A5 <a5@test.example>")
    );
    assert!(
        secret_chunk.metadata.date.is_some(),
        "git-history chunk must carry commit date"
    );
    assert!(
        secret_chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("a.txt")),
        "history chunk must carry file path metadata, got {:?}",
        secret_chunk.metadata.path
    );
    let commit = secret_chunk
        .metadata
        .commit
        .as_deref()
        .expect("git-history chunk must carry commit id");
    assert_eq!(commit.len(), 40, "commit id must be a full SHA-1");
    assert!(
        commit.chars().all(|c| c.is_ascii_hexdigit()),
        "commit id must be hex, got {commit:?}"
    );
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
