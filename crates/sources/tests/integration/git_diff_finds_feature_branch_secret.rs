//! GitDiffSource must diff base..head and surface added secrets.

#[cfg(feature = "git")]
use crate::support::split_chunk_results;
#[cfg(feature = "git")]
use keyhog_core::Source;

#[cfg(feature = "git")]
#[test]
fn git_diff_finds_feature_branch_secret() {
    use keyhog_sources::GitDiffSource;
    use std::process::Command;

    let (_guard, repo) = crate::support::git::init_repo();
    crate::support::git::commit(
        &repo,
        "base.txt",
        "stable=1
",
        "base",
    );
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(&repo)
        .output()
        .expect("branch");
    crate::support::git::commit(
        &repo,
        "new.env",
        "SLACK=xoxb-integrationDiffBranch00000001
",
        "feature",
    );

    let source = GitDiffSource::new(repo, "main").with_head_ref("feature");
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid GitDiffSource fixture must not emit SourceError rows, got {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "single feature-branch file should emit one diff chunk, got {chunks:?}"
    );
    let chunk = chunks[0];
    assert_eq!(chunk.metadata.source_type.as_ref(), "git-diff");
    assert_eq!(chunk.metadata.author.as_deref(), Some("LR1 A5"));
    assert!(
        chunk.metadata.date.is_some(),
        "git-diff chunk must carry commit date"
    );
    assert!(
        chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("new.env")),
        "diff chunk must carry added file path metadata, got {:?}",
        chunk.metadata.path
    );
    let commit = chunk
        .metadata
        .commit
        .as_deref()
        .expect("git-diff chunk must carry commit id");
    assert_eq!(commit.len(), 40, "commit id must be a full SHA-1");
    assert!(
        commit.chars().all(|c| c.is_ascii_hexdigit()),
        "commit id must be hex, got {commit:?}"
    );
    let bodies: Vec<String> = chunks.iter().map(|c| c.data.as_str().to_owned()).collect();
    assert!(
        bodies
            .iter()
            .any(|b| b.contains(concat!("xox", "b-integrationDiffBranch"))),
        "diff must include added file content; got {bodies:?}"
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_diff_integration_requires_git() {
    assert!(!cfg!(feature = "git"));
}
