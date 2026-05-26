#[cfg(feature = "git")]
use keyhog_core::Source;
#[cfg(feature = "git")]
use keyhog_sources::GitHistorySource;
#[cfg(feature = "git")]
use std::path::PathBuf;
#[cfg(feature = "git")]
use std::process::Command;

#[cfg(feature = "git")]
fn create_test_repo() -> (tempfile::TempDir, PathBuf) {
    let temp_dir = tempfile::tempdir().unwrap();
    let repo_path = temp_dir.path().to_path_buf();

    let output = Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(&repo_path)
        .output()
        .expect("failed to execute git init");
    assert!(output.status.success(), "git init failed: {output:?}");

    Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test User"])
        .current_dir(&repo_path)
        .output()
        .unwrap();

    (temp_dir, repo_path)
}

#[cfg(feature = "git")]
fn commit_file(repo_path: &PathBuf, filename: &str, content: &str, message: &str) {
    std::fs::write(repo_path.join(filename), content).unwrap();
    Command::new("git")
        .args(["add", filename])
        .current_dir(repo_path)
        .output()
        .unwrap();
    let output = Command::new("git")
        .args(["commit", "-m", message])
        .current_dir(repo_path)
        .output()
        .expect("failed to commit");
    assert!(output.status.success(), "git commit failed: {output:?}");
}

#[cfg(feature = "git")]
#[test]
fn git_history_source_collects_added_files_commit_by_commit() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "first.txt", "api_key = sk-first", "Add first");
    commit_file(&repo_path, "second.txt", "token = sk-second", "Add second");

    let source = GitHistorySource::new(repo_path);
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert_eq!(source.name(), "git-history");
    assert_eq!(chunks.len(), 2);
    assert!(chunks
        .iter()
        .any(|chunk| chunk.metadata.path.as_deref() == Some("first.txt")));
    assert!(chunks
        .iter()
        .any(|chunk| chunk.metadata.path.as_deref() == Some("second.txt")));
    // Don't just assert .is_some() — those would still pass if the
    // walker emitted empty strings or static placeholders. Pin the
    // ACTUAL git-commit shape: 40-char hex SHA, the test-config
    // author "Test User <test@example.com>", and a non-empty date
    // string. Each of these would have caught the
    // "we silently dropped commit.author from the chunk metadata"
    // regression class.
    for chunk in &chunks {
        let commit = chunk
            .metadata
            .commit
            .as_deref()
            .expect("commit must be set");
        assert!(
            commit.len() == 40 && commit.chars().all(|c| c.is_ascii_hexdigit()),
            "commit must be 40-char hex SHA; got {commit:?}"
        );

        let author = chunk
            .metadata
            .author
            .as_deref()
            .expect("author must be set");
        assert!(
            author.contains("test@example.com"),
            "author must include the configured test email; got {author:?}"
        );
        assert!(
            author.contains("Test User"),
            "author must include the configured test name; got {author:?}"
        );

        let date = chunk.metadata.date.as_deref().expect("date must be set");
        assert!(
            date.len() >= 10,
            "date must be a non-empty timestamp (≥10 chars to cover YYYY-MM-DD); got {date:?}"
        );
    }
}

#[cfg(feature = "git")]
#[test]
fn git_history_source_honors_max_commits() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "first.txt", "api_key = sk-first", "Add first");
    commit_file(&repo_path, "second.txt", "token = sk-second", "Add second");

    let chunks: Vec<_> = GitHistorySource::new(repo_path)
        .with_max_commits(1)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].metadata.path.as_deref(), Some("second.txt"));
}

#[cfg(feature = "git")]
#[test]
fn git_history_source_ignores_deleted_file_hunks() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(
        &repo_path,
        "temp.txt",
        "TEMP_SECRET = sk-should-not-resurface\n",
        "Add temp",
    );
    std::fs::write(repo_path.join("temp.txt"), "removed\n").unwrap();
    Command::new("git")
        .args(["add", "temp.txt"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    let output = Command::new("git")
        .args(["commit", "-m", "Remove temp"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    assert!(output.status.success());

    let chunks: Vec<_> = GitHistorySource::new(repo_path)
        .with_max_commits(1)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert!(
        chunks
            .iter()
            .all(|c| !c.data.contains("sk-should-not-resurface")),
        "deleted-file hunks must not resurface removed secrets; got {chunks:?}"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_history_source_rejects_non_repository_path() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("plain.txt"), "not a repo").unwrap();

    let err = GitHistorySource::new(dir.path().to_path_buf())
        .chunks()
        .next()
        .expect("non-repo should yield Err")
        .expect_err("non-repo path must be rejected");

    assert!(
        err.to_string().contains("not a git repository"),
        "expected git repository validation error; got {err}"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_history_source_sanitizes_traversal_paths_in_metadata() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(
        &repo_path,
        "safe.txt",
        "TOKEN = sk-safe-path\n",
        "Add safe file",
    );

    let chunks: Vec<_> = GitHistorySource::new(repo_path)
        .with_max_commits(1)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    for chunk in &chunks {
        if let Some(path) = chunk.metadata.path.as_deref() {
            assert!(
                !path.contains("..") && !path.starts_with('/'),
                "metadata path must be repo-relative and normalized; got {path:?}"
            );
        }
    }
}
