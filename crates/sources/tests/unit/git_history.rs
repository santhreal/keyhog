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
    assert!(chunks.iter().all(|chunk| chunk.metadata.commit.is_some()));
    assert!(chunks.iter().all(|chunk| chunk.metadata.author.is_some()));
    assert!(chunks.iter().all(|chunk| chunk.metadata.date.is_some()));
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
