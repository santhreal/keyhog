//! GitSource must emit blob content from tracked files.

#[cfg(feature = "git")]
use crate::support::split_chunk_results;
#[cfg(feature = "git")]
use keyhog_core::Source;

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
        "single tracked secret should emit exactly one Git chunk, got {chunks:?}"
    );
    let chunk = chunks[0];
    assert_eq!(chunk.metadata.source_type.as_ref(), "git/head");
    assert_eq!(chunk.metadata.author.as_deref(), Some("LR1 A5"));
    assert_eq!(
        chunk.metadata.size_bytes,
        Some("GITHUB_TOKEN=ghp_integrationGitSourceTest00000001\n".len() as u64)
    );
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
            .is_some_and(|path| path.ends_with("secrets.env")),
        "git chunk must carry tracked blob path, got {:?}",
        chunk.metadata.path
    );
    assert!(
        chunk.data.contains("ghp_integrationGitSourceTest"),
        "git source must surface blob text; got {:?}",
        chunk.data.to_string()
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_source_integration_requires_git() {
    assert!(!cfg!(feature = "git"));
}
