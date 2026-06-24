#[cfg(feature = "git")]
use keyhog_core::Source;
#[cfg(feature = "git")]
use keyhog_sources::{GitDiffSource, SourceLimits};
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
    assert_eq!(
        chunks.len(),
        2,
        "expected one chunk per hunk; got {chunks:?}"
    );
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
fn git_diff_hunk_flush_uses_resolved_git_blob_byte_cap() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "seed.txt", "seed = true\n", "base");
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    commit_file(
        &repo_path,
        "big.txt",
        "line_one\nline_two\nline_three\n",
        "add multi-line hunk",
    );

    let mut limits = SourceLimits::default();
    limits.git_blob_bytes = 12;

    let chunks: Vec<_> = GitDiffSource::new(repo_path, "main")
        .with_head_ref("feature")
        .with_limits(limits)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    assert!(
        chunks.len() >= 2,
        "git-diff hunk buffering must honor SourceLimits::git_blob_bytes; got {chunks:?}"
    );
    let joined = chunks
        .iter()
        .map(|chunk| chunk.data.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    for expected in ["line_one", "line_two", "line_three"] {
        assert!(
            joined.contains(expected),
            "split git-diff chunks must preserve added line {expected:?}; got {chunks:?}"
        );
    }
}

#[cfg(feature = "git")]
#[test]
fn git_diff_source_honors_aggregate_chunk_cap() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "seed.txt", "seed = true\n", "base");
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    commit_file(&repo_path, "first.txt", "FIRST=visible\n", "add first");
    commit_file(
        &repo_path,
        "second.txt",
        "SECOND=not reached\n",
        "add second",
    );

    let mut limits = SourceLimits::default();
    limits.git_chunk_count = 1;

    let rows: Vec<_> = GitDiffSource::new(repo_path, "main")
        .with_head_ref("feature")
        .with_limits(limits)
        .chunks()
        .collect();
    let ok_chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();

    assert_eq!(
        ok_chunks.len(),
        1,
        "git-diff must emit the first scanned hunk before enforcing the aggregate chunk cap"
    );
    assert_eq!(
        errors.len(),
        1,
        "git-diff aggregate chunk cap must surface one truncation error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("git diff source was truncated")
            && err.contains("aggregate chunk cap")
            && err.contains("remaining changed lines were not scanned"),
        "error must describe partial git-diff coverage; got {err}"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_diff_source_honors_aggregate_byte_cap() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "seed.txt", "seed = true\n", "base");
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    commit_file(&repo_path, "first.txt", "FIRST=visible\n", "add first");
    commit_file(
        &repo_path,
        "second.txt",
        "SECOND=not reached\n",
        "add second",
    );

    let mut limits = SourceLimits::default();
    limits.git_total_bytes = 1;

    let rows: Vec<_> = GitDiffSource::new(repo_path, "main")
        .with_head_ref("feature")
        .with_limits(limits)
        .chunks()
        .collect();
    let ok_chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();

    assert_eq!(
        ok_chunks.len(),
        1,
        "git-diff must emit the first scanned hunk before enforcing the aggregate byte cap"
    );
    assert_eq!(
        errors.len(),
        1,
        "git-diff aggregate byte cap must surface one truncation error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("git diff source was truncated")
            && err.contains("aggregate byte cap")
            && err.contains("remaining changed lines were not scanned"),
        "error must describe partial git-diff coverage; got {err}"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_diff_untracked_worktree_chunks_share_aggregate_cap() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "seed.txt", "seed = true\n", "base");
    std::fs::write(repo_path.join("first-untracked.txt"), "FIRST=visible\n").unwrap();
    std::fs::write(
        repo_path.join("second-untracked.txt"),
        "SECOND=not reached\n",
    )
    .unwrap();

    let mut limits = SourceLimits::default();
    limits.git_chunk_count = 1;

    let rows: Vec<_> = GitDiffSource::new(repo_path, "HEAD")
        .with_limits(limits)
        .chunks()
        .collect();
    let ok_chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();

    assert_eq!(
        ok_chunks.len(),
        1,
        "git-diff must emit one untracked worktree chunk before enforcing the aggregate chunk cap"
    );
    assert_eq!(
        errors.len(),
        1,
        "git-diff aggregate chunk cap must stop additional untracked worktree chunks"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("git diff source was truncated")
            && err.contains("aggregate chunk cap")
            && err.contains("remaining changed lines were not scanned"),
        "error must describe partial git-diff untracked coverage; got {err}"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_diff_yields_tracked_chunks_before_untracked_file_errors() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "tracked.txt", "base = true\n", "base");
    std::fs::write(
        repo_path.join("tracked.txt"),
        "base = true\ntracked_secret = sk-live-tracked\n",
    )
    .unwrap();
    std::fs::write(repo_path.join("oversized-untracked.txt"), "x".repeat(4096)).unwrap();

    let mut limits = SourceLimits::default();
    limits.git_blob_bytes = 1024;
    let source = GitDiffSource::new(repo_path, "HEAD").with_limits(limits);
    let mut chunks = source.chunks();

    let first = chunks
        .next()
        .expect("tracked diff chunk should be yielded first")
        .expect("tracked diff chunk must not be blocked by untracked-file errors");
    assert!(
        first.data.contains("tracked_secret = sk-live-tracked"),
        "first git-diff chunk must come from the tracked worktree diff; got {first:?}"
    );

    let second = chunks
        .next()
        .expect("oversized untracked file should surface after tracked chunks");
    let error = second.expect_err("untracked oversized file must surface as an error");
    let message = error.to_string();
    assert!(
        message.contains("oversized-untracked.txt")
            && message.contains("exceeds git_blob_bytes limit"),
        "expected untracked size-cap error after tracked chunk, got {message}"
    );
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
    assert_eq!(
        chunks[0].metadata.author.as_deref(),
        Some("Test User"),
        "git-diff metadata must carry author from git log"
    );
    let date = chunks[0]
        .metadata
        .date
        .as_deref()
        .expect("commit date must be set");
    let timezone_sign = date.as_bytes().get(date.len().saturating_sub(6)).copied();
    assert!(
        date.contains('T') && matches!(timezone_sign, Some(b'+') | Some(b'-')),
        "git-diff metadata must carry ISO author date; got {date:?}"
    );
    assert!(
        chunks[0]
            .data
            .contains("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab"),
        "added line content must be present; got {:?}",
        chunks[0].data
    );
}

#[cfg(feature = "git")]
#[test]
fn git_diff_source_scans_quoted_tab_path_headers() {
    let (_temp_dir, repo_path) = create_test_repo();
    let filename = "tab\tfile.txt";
    commit_file(&repo_path, filename, "clean = true\n", "Initial");
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    commit_file(
        &repo_path,
        filename,
        "clean = true\nQUOTED_TAB_SECRET = ghp_quotedTabPathHeader0000000000001\n",
        "Add quoted path secret",
    );
    let config = Command::new("git")
        .args(["config", "diff.noprefix", "true"])
        .current_dir(&repo_path)
        .output()
        .expect("failed to set diff.noprefix");
    assert!(config.status.success(), "git config failed: {config:?}");

    let source = GitDiffSource::new(repo_path, "main").with_head_ref("feature");
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();
    let chunk = chunks
        .iter()
        .find(|chunk| chunk.data.contains("ghp_quotedTabPathHeader0000000000001"))
        .expect("git-diff must scan added lines for quoted path headers");

    assert_eq!(
        chunk.metadata.path.as_deref(),
        Some("tab\tfile.txt"),
        "quoted git path metadata must be exact and prefix-stable without dropping the hunk"
    );
}

#[cfg(feature = "git")]
#[test]
fn git_diff_source_decodes_quoted_quote_and_utf8_paths() {
    let (_temp_dir, repo_path) = create_test_repo();
    commit_file(&repo_path, "seed.txt", "clean = true\n", "Initial");
    Command::new("git")
        .args(["checkout", "-b", "feature"])
        .current_dir(&repo_path)
        .output()
        .unwrap();
    commit_file(
        &repo_path,
        "quote\"x.txt",
        "QUOTE_PATH_SECRET = ghp_quotedQuotePathHeader0000000001\n",
        "Add quote path secret",
    );
    commit_file(
        &repo_path,
        "unic\u{f6}de.txt",
        "UTF8_PATH_SECRET = ghp_quotedUtf8PathHeader00000000001\n",
        "Add utf8 path secret",
    );

    let source = GitDiffSource::new(repo_path, "main").with_head_ref("feature");
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    let quote_chunk = chunks
        .iter()
        .find(|chunk| chunk.data.contains("ghp_quotedQuotePathHeader0000000001"))
        .expect("git-diff must scan added lines for quoted double-quote paths");
    assert_eq!(quote_chunk.metadata.path.as_deref(), Some("quote\"x.txt"));

    let utf8_chunk = chunks
        .iter()
        .find(|chunk| chunk.data.contains("ghp_quotedUtf8PathHeader00000000001"))
        .expect("git-diff must scan added lines for quoted UTF-8 paths");
    assert_eq!(
        utf8_chunk.metadata.path.as_deref(),
        Some("unic\u{f6}de.txt")
    );
}
