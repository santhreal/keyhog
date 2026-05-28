#[cfg(feature = "git")]
#[test]
fn git_diff_head_includes_untracked_worktree_file() {
    use keyhog_core::Source;
    use keyhog_sources::GitDiffSource;
    use std::path::PathBuf;
    use std::process::Command;

    let temp_dir = tempfile::tempdir().unwrap();
    let repo_path = temp_dir.path().to_path_buf();
    Command::new("git")
        .args(["init", "-b", "main", "-q"])
        .current_dir(&repo_path)
        .status()
        .unwrap();
    Command::new("git")
        .args(["config", "user.email", "t@test"])
        .current_dir(&repo_path)
        .status()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "T"])
        .current_dir(&repo_path)
        .status()
        .unwrap();
    std::fs::write(repo_path.join("tracked.txt"), "ok\n").unwrap();
    Command::new("git")
        .args(["add", "tracked.txt"])
        .current_dir(&repo_path)
        .status()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "init", "-q"])
        .current_dir(&repo_path)
        .status()
        .unwrap();
    std::fs::write(
        repo_path.join("new-secret.env"),
        "AWS_ACCESS_KEY_ID=AKIAKPQXRMSNTBVWYZBN\n",
    )
    .unwrap();

    let source = GitDiffSource::new(PathBuf::from(&repo_path), "HEAD");
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(chunks.len(), 1);
    assert!(
        chunks[0].data.contains("AKIAKPQXRMSNTBVWYZBN"),
        "untracked worktree file must be scanned under --git-diff HEAD semantics"
    );
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("new-secret.env")
    );
}

#[cfg(not(feature = "git"))]
#[test]
fn git_diff_head_worktree_requires_git_feature() {}
