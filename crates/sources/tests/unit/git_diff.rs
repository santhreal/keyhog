#[cfg(feature = "git")]
use keyhog_core::Source;
#[cfg(feature = "git")]
use keyhog_sources::GitDiffSource;
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
fn git_diff_source_finds_added_lines_without_deleted_content() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(
        &repo_path,
        "config.txt",
        "old_secret_key = sk-old\nother = value",
        "Initial",
    );
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    commit_file(
        &repo_path,
        "config.txt",
        "new_secret_key = sk-new\nother = value",
        "Update",
    );

    let source = GitDiffSource::new(repo_path, "main").with_head_ref("feature");
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert_eq!(source.name(), "git-diff");
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].data.contains("sk-new"));
    assert!(!chunks[0].data.contains("sk-old"));
}

#[cfg(feature = "git")]
#[test]
fn git_diff_source_rejects_nonexistent_ref() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "file.txt", "content", "Initial commit");

    let source = GitDiffSource::new(repo_path, "nonexistent-branch");
    let chunk_collection: Result<Vec<_>, _> = source.chunks().collect();

    assert!(chunk_collection.is_err());
}
