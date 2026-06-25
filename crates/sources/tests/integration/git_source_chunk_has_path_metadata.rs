//! GitSource chunks must include file path metadata.

#[cfg(feature = "git")]
use crate::support::split_chunk_results;
#[cfg(feature = "git")]
use keyhog_core::Source;

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

    let source = GitSource::new(repo).with_max_commits(1);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid GitSource fixture must not emit SourceError rows, got {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "single tracked file should emit exactly one Git chunk, got {chunks:?}"
    );
    let chunk = chunks[0];
    assert_eq!(chunk.metadata.source_type, "git/head");
    assert_eq!(chunk.metadata.author.as_deref(), Some("LR1 A5"));
    assert_eq!(chunk.metadata.size_bytes, Some("X=1\n".len() as u64));
    let commit = chunk
        .metadata
        .commit
        .as_deref()
        .expect("git/head chunk must carry commit id");
    assert_eq!(commit.len(), 40, "commit id must be a full SHA-1");
    assert!(
        commit.chars().all(|c| c.is_ascii_hexdigit()),
        "commit id must be hex, got {commit:?}"
    );
    assert!(
        chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("tracked.env")),
        "git chunk must carry blob path; got {:?}",
        chunk.metadata.path
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_chunk_path_requires_git() {
    assert!(!cfg!(feature = "git"));
}
