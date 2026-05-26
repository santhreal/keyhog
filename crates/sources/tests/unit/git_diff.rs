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

#[cfg(feature = "git")]
#[test]
fn git_diff_source_skips_deleted_file_without_added_lines() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(
        &repo_path,
        "remove.txt",
        "REMOVED_SECRET = sk-deleted\n",
        "Add removable",
    );
    Command::new("git")
        .args(["checkout", "-b", "prune"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    std::fs::remove_file(repo_path.join("remove.txt")).unwrap();
    Command::new("git")
        .args(["rm", "remove.txt"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    let output = Command::new("git")
        .args(["commit", "-m", "Delete secret file"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    assert!(output.status.success());

    let source = GitDiffSource::new(repo_path, "main").with_head_ref("prune");
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert!(
        chunks.is_empty(),
        "delete-only diff must not emit added-line chunks; got {chunks:?}"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_diff_source_rejects_unsafe_ref_names() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "file.txt", "content", "Initial commit");

    let source = GitDiffSource::new(repo_path, "../evil");
    let err = source
        .chunks()
        .next()
        .expect("unsafe ref should yield one Err")
        .expect_err("unsafe ref must be rejected");
    assert!(
        err.to_string().contains("unsafe git ref"),
        "expected unsafe ref rejection; got {err}"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_diff_source_chunk_metadata_carries_path_and_commit() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "first.txt", "line = 1\n", "Initial");
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    commit_file(
        &repo_path,
        "secrets.env",
        "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab\n",
        "Add secret",
    );

    let source = GitDiffSource::new(repo_path.clone(), "main").with_head_ref("feature");
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    assert_eq!(chunks.len(), 1);
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some("secrets.env"),
        "added file path must appear in chunk metadata"
    );
    let commit = chunks[0]
        .metadata
        .commit
        .as_deref()
        .expect("commit hash must be set");
    assert!(
        commit.len() == 40 && commit.chars().all(|c| c.is_ascii_hexdigit()),
        "commit must be 40-char hex SHA; got {commit:?}"
    );
    assert!(
        chunks[0].data.contains("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab"),
        "added line content must be present; got {:?}",
        chunks[0].data
    );
}
