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

/// Regression: each diff hunk's chunk must carry `base_line = new_start - 1`
/// so a scanner counting a match's line within the chunk reports the absolute
/// new-file line, not the chunk-local line. Before the fix every diff finding
/// was attributed to line 1 (the start of the concatenated added-line blob),
/// making `--git-diff` (the pre-commit / CI "scan only changed lines"
/// workflow) point nowhere near the leak.
#[cfg(feature = "git")]
#[test]
fn git_diff_chunks_carry_absolute_base_line_per_hunk() {
    let (_temp_dir, repo_path) = create_test_repo();
    // 300-line base file.
    let base: String = (1..=300).map(|i| format!("base_{i} = {i}\n")).collect();
    commit_file(&repo_path, "f.txt", &base, "base");
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    // Edit two far-apart lines (10 and 200) so `git diff -U0` yields two
    // separate hunks → two chunks with distinct base lines.
    let mut lines: Vec<String> = (1..=300).map(|i| format!("base_{i} = {i}")).collect();
    lines[9] = "k1 = \"AKIAQYLPMN5HFIQR7XYA\"".to_string();
    lines[199] = "k2 = \"AKIA2B3C4D5E6F7G2H3J\"".to_string();
    commit_file(&repo_path, "f.txt", &(lines.join("\n") + "\n"), "two edits");

    let source = GitDiffSource::new(repo_path, "main").with_head_ref("feature");
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    // One chunk per hunk.
    assert_eq!(chunks.len(), 2, "expected one chunk per hunk; got {chunks:?}");
    // Match each chunk to its hunk by content and assert its base line is the
    // new-file start minus one (line 10 -> base_line 9, line 200 -> 199).
    for c in &chunks {
        let data = c.data.as_ref();
        if data.contains("AKIAQYLPMN5HFIQR7XYA") {
            assert_eq!(
                c.metadata.base_line, 9,
                "hunk adding line 10 must carry base_line 9; got {}",
                c.metadata.base_line
            );
        } else if data.contains("AKIA2B3C4D5E6F7G2H3J") {
            assert_eq!(
                c.metadata.base_line, 199,
                "hunk adding line 200 must carry base_line 199; got {}",
                c.metadata.base_line
            );
        } else {
            panic!("unexpected diff chunk content: {data:?}");
        }
    }
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
        chunks[0]
            .data
            .contains("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab"),
        "added line content must be present; got {:?}",
        chunks[0].data
    );
}
