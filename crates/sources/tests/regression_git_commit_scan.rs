//! Regression coverage for git commit/blob scanning: `GitSource` (whole-object
//! walk that labels blobs `git/head` vs `git/history` vs `git/unreachable`),
//! `GitHistorySource` (added-line reconstruction, `git-history`), and
//! `GitDiffSource` ref validation (`git-diff`).
//!
//! Every assertion pins a CONCRETE expected value — the exact `source_type`
//! string, the exact committed-file byte length, a 40-char hex commit id, an
//! error substring, or an exact chunk count. No `is_empty`/`is_some`-only
//! assertions. The canonical GitHub classic PAT `ghp_0000…2C8GjS` carries a
//! valid trailing CRC so it survives checksum-gated detectors; here we assert
//! that the SOURCE surfaces the blob text (scanning happens downstream), so the
//! literal is used only as a byte-exact sentinel inside the chunk data.

#![cfg(unix)]

mod support;

#[cfg(feature = "git")]
mod git_commit_scan {
    use super::support::git::{commit, init_repo};
    use super::support::split_chunk_results;
    use keyhog_core::{Chunk, Source};
    use keyhog_sources::{GitDiffSource, GitHistorySource, GitSource};

    /// A committed line whose value is the canonical valid-CRC GitHub PAT used as
    /// a byte-exact sentinel. The trailing newline is part of the committed blob,
    /// so `size_bytes` assertions include it.
    const TOKEN: &str = "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";
    const TOKEN_LINE: &str = "GITHUB_TOKEN=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\n";

    /// Collect owned `GitSource` chunks plus stringified error rows for `repo`.
    fn git_scan(repo: &std::path::Path, max_commits: usize) -> (Vec<Chunk>, Vec<String>) {
        let source = GitSource::new(repo.to_path_buf()).with_max_commits(max_commits);
        let rows: Vec<_> = source.chunks().collect();
        let (chunk_refs, err_refs) = split_chunk_results(&rows);
        let chunks = chunk_refs.into_iter().cloned().collect();
        let errors = err_refs.into_iter().map(|e| e.to_string()).collect();
        (chunks, errors)
    }

    /// Collect owned `GitHistorySource` chunks plus stringified error rows.
    fn history_scan(repo: &std::path::Path, max_commits: usize) -> (Vec<Chunk>, Vec<String>) {
        let source = GitHistorySource::new(repo.to_path_buf()).with_max_commits(max_commits);
        let rows: Vec<_> = source.chunks().collect();
        let (chunk_refs, err_refs) = split_chunk_results(&rows);
        let chunks = chunk_refs.into_iter().cloned().collect();
        let errors = err_refs.into_iter().map(|e| e.to_string()).collect();
        (chunks, errors)
    }

    fn assert_full_hex_commit(commit_id: &str) {
        assert_eq!(commit_id.len(), 40, "commit id must be a full SHA-1 hex");
        assert!(
            commit_id.chars().all(|c| c.is_ascii_hexdigit()),
            "commit id must be all hex, got {commit_id:?}"
        );
    }

    // ---- GitSource (whole-object blob walk) ---------------------------------

    #[test]
    fn committed_blob_surfaces_as_git_head_chunk_with_exact_metadata() {
        let (_g, repo) = init_repo();
        commit(&repo, "secrets.env", TOKEN_LINE, "add token");

        let (chunks, errors) = git_scan(&repo, 1);
        assert_eq!(
            errors.len(),
            0,
            "clean fixture must emit no error rows: {errors:?}"
        );
        assert_eq!(
            chunks.len(),
            1,
            "one tracked file => exactly one blob chunk"
        );

        let chunk = &chunks[0];
        assert_eq!(chunk.metadata.source_type.as_ref(), "git/head");
        assert_eq!(chunk.metadata.author.as_deref(), Some("LR1 A5"));
        assert_eq!(chunk.metadata.size_bytes, Some(TOKEN_LINE.len() as u64));
        // GitSource sets positional bases to 0 and does NOT populate a date.
        assert_eq!(chunk.metadata.base_line, 0);
        assert_eq!(chunk.metadata.base_offset, 0);
        assert_eq!(chunk.metadata.date, None);

        let commit_id = chunk
            .metadata
            .commit
            .as_deref()
            .expect("git/head chunk must carry commit id");
        assert_full_hex_commit(commit_id);
        assert!(
            chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|p| p.ends_with("secrets.env")),
            "chunk must carry the committed blob path, got {:?}",
            chunk.metadata.path
        );
        assert!(
            chunk.data.contains(TOKEN),
            "chunk data must carry the committed blob text"
        );
    }

    #[test]
    fn blob_removed_from_head_is_labeled_git_history_not_head() {
        let (_g, repo) = init_repo();
        commit(&repo, "app.env", TOKEN_LINE, "add token");
        commit(&repo, "app.env", "TOKEN=redacted\n", "remove token");

        let (chunks, errors) = git_scan(&repo, 10);
        assert_eq!(
            errors.len(),
            0,
            "clean fixture must emit no error rows: {errors:?}"
        );

        // The token-bearing blob is only in the older commit's tree.
        let token_chunk = chunks
            .iter()
            .find(|c| c.data.contains(TOKEN))
            .expect("the removed-from-HEAD token blob must still surface");
        assert_eq!(
            token_chunk.metadata.source_type.as_ref(),
            "git/history",
            "a blob absent from HEAD's tree is history, not head"
        );

        // The current HEAD version of the same path is labeled git/head.
        let head_chunk = chunks
            .iter()
            .find(|c| c.data.contains("TOKEN=redacted"))
            .expect("HEAD's current blob must surface");
        assert_eq!(head_chunk.metadata.source_type.as_ref(), "git/head");

        // Nothing carrying the token may be mislabeled as live HEAD content.
        assert_eq!(
            chunks
                .iter()
                .filter(|c| c.data.contains(TOKEN) && c.metadata.source_type.as_ref() == "git/head")
                .count(),
            0,
            "the removed token must never be labeled git/head"
        );
    }

    #[test]
    fn two_committed_files_yield_two_distinct_head_chunks() {
        let (_g, repo) = init_repo();
        commit(&repo, "a.env", TOKEN_LINE, "add a");
        commit(&repo, "b.txt", "hello world\n", "add b");

        let (chunks, errors) = git_scan(&repo, 10);
        assert_eq!(
            errors.len(),
            0,
            "clean fixture must emit no error rows: {errors:?}"
        );
        assert_eq!(chunks.len(), 2, "two tracked files => two blob chunks");
        assert!(
            chunks
                .iter()
                .all(|c| c.metadata.source_type.as_ref() == "git/head"),
            "both current-tree blobs are git/head"
        );

        let mut suffixes: Vec<String> = chunks
            .iter()
            .map(|c| {
                c.metadata
                    .path
                    .as_deref()
                    .map(|p| p.rsplit('/').next().unwrap_or(p).to_string())
                    .unwrap_or_default()
            })
            .collect();
        suffixes.sort();
        assert_eq!(suffixes, vec!["a.env".to_string(), "b.txt".to_string()]);

        assert_eq!(
            chunks.iter().filter(|c| c.data.contains(TOKEN)).count(),
            1,
            "exactly the a.env blob carries the token"
        );
    }

    #[test]
    fn max_commits_zero_scans_no_commit_blobs() {
        // `git log --max-count 0` enumerates nothing, and a clean fixture has no
        // unreachable/dangling objects, so the whole scan is empty.
        let (_g, repo) = init_repo();
        commit(&repo, "x.env", TOKEN_LINE, "add token");

        let (chunks, errors) = git_scan(&repo, 0);
        assert_eq!(chunks.len(), 0, "max_commits(0) must scan zero blobs");
        assert_eq!(
            errors.len(),
            0,
            "no work also means no error rows: {errors:?}"
        );
    }

    #[test]
    fn binary_blob_is_surfaced_as_skip_error_and_never_scanned() {
        // A PDF-magic blob decodes to no text; GitSource must NOT emit it as a
        // scannable chunk but MUST surface a loud "not scanned" error row.
        let (_g, repo) = init_repo();
        let body = "%PDF-1.7\nGITHUB_TOKEN=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 trailing\n";
        commit(&repo, "blob.pdf", body, "add pdf blob");

        let (chunks, errors) = git_scan(&repo, 1);
        assert_eq!(
            chunks.iter().filter(|c| c.data.contains(TOKEN)).count(),
            0,
            "a binary blob must never be surfaced as scannable text"
        );
        assert_eq!(
            chunks.len(),
            0,
            "the only blob is binary => zero text chunks"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("is binary and was not decoded as text")
                    && e.contains("blob.pdf")
                    && e.contains("blob was not scanned")),
            "binary skip must be a loud, path-tagged error row, got {errors:?}"
        );
    }

    #[test]
    fn git_source_name_is_git() {
        let source = GitSource::new(std::path::PathBuf::from("."));
        assert_eq!(source.name(), "git");
    }

    #[test]
    fn nonexistent_repo_path_errors_with_not_a_repository_reason() {
        // `validate_repo_path` canonicalizes then rejects a non-`.git` dir.
        let dir = tempfile::tempdir().unwrap();
        let source = GitSource::new(dir.path().to_path_buf());
        let first = source
            .chunks()
            .next()
            .expect("non-repo must yield one iterator item");
        let err = first.expect_err("a plain temp dir is not a git repository");
        assert!(
            err.to_string().contains("is not a git repository"),
            "expected the not-a-repository reason, got {err}"
        );
    }

    // ---- GitHistorySource (added-line reconstruction) -----------------------

    #[test]
    fn history_source_surfaces_added_token_as_git_history_chunk() {
        let (_g, repo) = init_repo();
        commit(&repo, "config.env", TOKEN_LINE, "add token");

        let (chunks, errors) = history_scan(&repo, 10);
        assert_eq!(
            errors.len(),
            0,
            "clean fixture must emit no error rows: {errors:?}"
        );

        let chunk = chunks
            .iter()
            .find(|c| c.metadata.source_type.as_ref() == "git-history" && c.data.contains(TOKEN))
            .expect("added token must surface in a git-history chunk");
        let commit_id = chunk.metadata.commit.as_deref().expect("history commit id");
        assert_full_hex_commit(commit_id);
        // Unlike GitSource, the history source populates a commit date.
        assert!(
            chunk.metadata.date.is_some(),
            "history chunk carries commit date"
        );
        assert!(
            chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|p| p.ends_with("config.env")),
            "history chunk carries the file path, got {:?}",
            chunk.metadata.path
        );
    }

    #[test]
    fn history_source_name_is_git_history() {
        let source = GitHistorySource::new(std::path::PathBuf::from("."));
        assert_eq!(source.name(), "git-history");
    }

    #[test]
    fn history_source_finds_token_removed_from_head() {
        // Added in one commit, deleted in the next: absent from HEAD but present
        // in the added-line history, so the source must still surface it.
        let (_g, repo) = init_repo();
        commit(&repo, "creds.env", TOKEN_LINE, "add token");
        commit(&repo, "creds.env", "# rotated\n", "remove token");

        let (chunks, _errors) = history_scan(&repo, 10);
        assert_eq!(
            chunks
                .iter()
                .filter(
                    |c| c.metadata.source_type.as_ref() == "git-history" && c.data.contains(TOKEN)
                )
                .count(),
            1,
            "a token removed from HEAD must still surface exactly once in history"
        );
    }

    #[test]
    fn history_max_commits_one_excludes_older_token_commit() {
        let (_g, repo) = init_repo();
        commit(&repo, "old.env", TOKEN_LINE, "add token (oldest)");
        commit(&repo, "note.txt", "benign one\n", "benign 1");
        commit(&repo, "note.txt", "benign two\n", "benign 2");

        let (chunks, _errors) = history_scan(&repo, 1);
        assert_eq!(
            chunks.iter().filter(|c| c.data.contains(TOKEN)).count(),
            0,
            "with_max_commits(1) must not reach the older token-bearing commit"
        );
    }

    // ---- GitDiffSource (ref validation + added-line diff) -------------------

    #[test]
    fn git_diff_double_dot_base_ref_is_rejected_as_unsafe() {
        let (_g, repo) = init_repo();
        commit(&repo, "a.txt", "x=1\n", "init");

        let source = GitDiffSource::new(repo, "bad..ref");
        assert_eq!(source.name(), "git-diff");
        let err = source
            .chunks()
            .next()
            .expect("must yield an item")
            .expect_err("a `..` range is an unsafe ref and must be refused");
        assert!(
            err.to_string().contains("unsafe git ref"),
            "expected the unsafe-ref reason, got {err}"
        );
    }

    #[test]
    fn git_diff_nonexistent_base_ref_errors_not_found() {
        let (_g, repo) = init_repo();
        commit(&repo, "a.txt", "x=1\n", "init");

        let err = GitDiffSource::new(repo, "no-such-ref-xyz")
            .chunks()
            .next()
            .expect("must yield an item")
            .expect_err("a missing base ref must fail");
        assert!(
            err.to_string().contains("not found"),
            "expected the not-found reason, got {err}"
        );
    }

    #[test]
    fn git_diff_surfaces_line_added_between_base_and_worktree() {
        // Base = HEAD~1 (before the token), worktree = HEAD (with the token):
        // the added token line must surface as a git-diff chunk.
        let (_g, repo) = init_repo();
        commit(&repo, "app.env", "BASE=1\n", "base");
        commit(
            &repo,
            "app.env",
            "BASE=1\nGITHUB_TOKEN=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\n",
            "add token",
        );

        let source = GitDiffSource::new(repo, "HEAD~1");
        let rows: Vec<_> = source.chunks().collect();
        let (chunk_refs, err_refs) = split_chunk_results(&rows);
        let errors: Vec<String> = err_refs.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            errors.len(),
            0,
            "clean diff fixture must emit no error rows: {errors:?}"
        );

        let chunk = chunk_refs
            .iter()
            .find(|c| c.data.contains(TOKEN))
            .expect("the newly added token line must surface in a git-diff chunk");
        assert_eq!(chunk.metadata.source_type.as_ref(), "git-diff");
        assert!(
            chunk
                .metadata
                .path
                .as_deref()
                .is_some_and(|p| p.ends_with("app.env")),
            "diff chunk carries the changed file path, got {:?}",
            chunk.metadata.path
        );
    }
}

#[cfg(not(feature = "git"))]
#[test]
fn git_commit_scan_regression_requires_git_feature() {
    assert!(
        !cfg!(feature = "git"),
        "this regression only runs with the git feature enabled"
    );
}
