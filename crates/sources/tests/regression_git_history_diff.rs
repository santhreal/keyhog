//! Regression lock for the git **history** (`GitHistorySource`) and **diff**
//! (`GitDiffSource`) added-line scan paths.
//!
//! These two sources are what a CI/pre-commit hook and a "scan the whole
//! history" audit rely on: `GitHistorySource` runs `git log -p -U0` and emits
//! every commit's *added* lines as chunks tagged `git-history`, while
//! `GitDiffSource` runs `git diff base..head -U0` and emits only the added
//! lines between two refs tagged `git-diff`. Both stamp each chunk with the
//! owning commit id, the author, and the author date so a finding can be traced
//! back to the exact commit that introduced it.
//!
//! Every test builds a real throwaway git repository, captures the concrete
//! commit ids / author dates that git itself produced (via `git rev-parse` /
//! `git log`), and asserts the source surfaced the planted secret with those
//! EXACT metadata values. Negative twins assert that deletions, unchanged
//! context, identical refs, and out-of-window commits contribute ZERO added
//! chunks, so a regression that either drops attribution or over-reports
//! removed content is caught, not masked by an `!is_empty()` check.

#![cfg(unix)]

mod support;

#[cfg(feature = "git")]
mod git_regression {
    use super::support::git::{commit, init_repo};
    use super::support::split_chunk_results;
    use keyhog_core::{Chunk, Source};
    use keyhog_sources::{GitDiffSource, GitHistorySource};
    use std::path::Path;
    use std::process::Command;

    // Unique, non-overlapping sentinels: a chunk that contains one could only
    // have come from the exact place it was planted.
    const FILE_SECRET: &str = "KEYHOGgitFILEsecret_AKIA0000FILE0000BLOB";
    const HISTORY_SECRET: &str = "KEYHOGgitHISTsecret_AKIA4444REMOVED4444";
    const ADDED_SECRET: &str = "aws_secret=AKIAADDEDSECRETADDEDSECRET00";

    // Fixtures set user.name = "LR1 A5" and user.email = "a5@test.example"
    // (see support::git::init_repo). GitHistorySource's log format is
    // `%an <%ae>`; GitDiffSource's metadata format is bare `%an`.
    const HISTORY_AUTHOR: &str = "LR1 A5 <a5@test.example>";
    const DIFF_AUTHOR: &str = "LR1 A5";

    // ---- runtime capture helpers ----------------------------------------

    /// The 40-char lowercase hex commit id `rev` resolves to, straight from git.
    fn rev_parse(repo: &Path, rev: &str) -> String {
        let out = Command::new("git")
            .args(["rev-parse", rev])
            .current_dir(repo)
            .output()
            .expect("git rev-parse");
        assert!(out.status.success(), "git rev-parse {rev} failed: {out:?}");
        let sha = String::from_utf8(out.stdout).expect("utf8 sha");
        sha.trim().to_string()
    }

    /// The author date of `rev` in strict-ISO form (`%aI`), the exact string the
    /// sources copy into `ChunkMetadata::date`.
    fn author_date_iso(repo: &Path, rev: &str) -> String {
        let out = Command::new("git")
            .args(["log", "-1", "--format=%aI", rev])
            .current_dir(repo)
            .output()
            .expect("git log date");
        assert!(out.status.success(), "git log date failed: {out:?}");
        let date = String::from_utf8(out.stdout).expect("utf8 date");
        date.trim().to_string()
    }

    /// Commit a whole new file with content and message, returning the resulting
    /// HEAD commit id.
    fn commit_returning_sha(repo: &Path, file: &str, content: &str, message: &str) -> String {
        commit(repo, file, content, message);
        rev_parse(repo, "HEAD")
    }

    fn collect_ok<S: Source + ?Sized>(source: &S) -> Vec<Chunk> {
        let rows: Vec<_> = source.chunks().collect();
        let (chunks, errors) = split_chunk_results(&rows);
        assert!(
            errors.is_empty(),
            "clean fixture source must not emit SourceError rows: {errors:?}"
        );
        chunks.into_iter().cloned().collect()
    }

    fn chunk_with<'a>(chunks: &'a [Chunk], needle: &str) -> Option<&'a Chunk> {
        chunks.iter().find(|c| c.data.contains(needle))
    }

    fn count_with(chunks: &[Chunk], needle: &str) -> usize {
        chunks.iter().filter(|c| c.data.contains(needle)).count()
    }

    // ---- source identity ------------------------------------------------

    #[test]
    fn history_source_name_is_git_history() {
        let (_g, repo) = init_repo();
        assert_eq!(GitHistorySource::new(repo).name(), "git-history");
    }

    #[test]
    fn diff_source_name_is_git_diff() {
        let (_g, repo) = init_repo();
        assert_eq!(GitDiffSource::new(repo, "HEAD").name(), "git-diff");
    }

    // ---- history: exact commit / author / date attribution --------------

    #[test]
    fn history_file_secret_surfaces_with_exact_commit_author_date() {
        let (_g, repo) = init_repo();
        let sha = commit_returning_sha(
            &repo,
            "creds.txt",
            &format!("secret={FILE_SECRET}\n"),
            "add creds",
        );
        let expected_date = author_date_iso(&repo, &sha);

        let source = GitHistorySource::new(repo.clone()).with_max_commits(50);
        let chunks = collect_ok(&source);
        let chunk =
            chunk_with(&chunks, FILE_SECRET).expect("git-history must surface the added secret");

        assert_eq!(chunk.metadata.source_type.as_ref(), "git-history");
        assert_eq!(chunk.metadata.path.as_deref(), Some("creds.txt"));
        assert_eq!(
            chunk.metadata.commit.as_deref(),
            Some(sha.as_str()),
            "history chunk carries the exact HEAD commit id git produced"
        );
        assert_eq!(
            chunk.metadata.author.as_deref(),
            Some(HISTORY_AUTHOR),
            "history author is `name <email>`"
        );
        assert_eq!(
            chunk.metadata.date.as_deref(),
            Some(expected_date.as_str()),
            "history date equals git's %aI author date verbatim"
        );
    }

    #[test]
    fn history_new_file_chunk_base_line_is_zero() {
        // A file introduced whole in one commit diffs as `@@ -0,0 +1,N @@`, so
        // the hunk's base line (`new_start - 1`) is exactly 0.
        let (_g, repo) = init_repo();
        commit(
            &repo,
            "creds.txt",
            &format!("secret={FILE_SECRET}\n"),
            "add",
        );
        let source = GitHistorySource::new(repo).with_max_commits(50);
        let chunks = collect_ok(&source);
        let chunk = chunk_with(&chunks, FILE_SECRET).expect("secret chunk present");
        assert_eq!(
            chunk.metadata.base_line, 0,
            "the first added line of a brand-new file is absolute line 1 (base_line 0)"
        );
    }

    #[test]
    fn history_removed_secret_attributed_to_owning_older_commit() {
        // The secret is added in commit 1 and rotated out in commit 2. History
        // must attribute the secret chunk to the OLDER commit that introduced
        // it, never to the rotation commit.
        let (_g, repo) = init_repo();
        let sha1 = commit_returning_sha(
            &repo,
            "config.txt",
            &format!("token={HISTORY_SECRET}\n"),
            "add token",
        );
        let sha2 = commit_returning_sha(&repo, "config.txt", "token=rotated\n", "rotate token");
        assert_ne!(sha1, sha2, "two distinct commits");

        let source = GitHistorySource::new(repo).with_max_commits(50);
        let chunks = collect_ok(&source);

        let secret_chunk =
            chunk_with(&chunks, HISTORY_SECRET).expect("removed secret still surfaces in history");
        assert_eq!(
            secret_chunk.metadata.commit.as_deref(),
            Some(sha1.as_str()),
            "secret is attributed to the commit that introduced it, not the rotation"
        );

        let rotated_chunk =
            chunk_with(&chunks, "token=rotated").expect("the rotation added line is also scanned");
        assert_eq!(
            rotated_chunk.metadata.commit.as_deref(),
            Some(sha2.as_str()),
            "the rotation added line is attributed to the rotation commit"
        );
    }

    #[test]
    fn history_max_commits_one_excludes_older_commit_secret() {
        // `--max-count 1` traverses only HEAD. The secret lives ONLY in the
        // earlier commit, so capping to one commit must drop it entirely while
        // still surfacing HEAD's own added line.
        let (_g, repo) = init_repo();
        commit(
            &repo,
            "config.txt",
            &format!("token={HISTORY_SECRET}\n"),
            "add token",
        );
        let sha2 = commit_returning_sha(&repo, "config.txt", "token=rotated\n", "rotate token");

        let source = GitHistorySource::new(repo).with_max_commits(1);
        let chunks = collect_ok(&source);
        assert_eq!(
            count_with(&chunks, HISTORY_SECRET),
            0,
            "the out-of-window commit's secret must not be traversed with max_commits(1)"
        );
        let rotated = chunk_with(&chunks, "token=rotated")
            .expect("HEAD's own added line is still scanned under the cap");
        assert_eq!(rotated.metadata.commit.as_deref(), Some(sha2.as_str()));
    }

    #[test]
    fn history_benign_repo_scans_content_but_has_zero_sentinel() {
        // Negative twin: a benign commit is scanned (its added line surfaces)
        // yet fabricates no secret sentinel.
        let (_g, repo) = init_repo();
        commit(
            &repo,
            "notes.txt",
            "just some ordinary notes\n",
            "add notes",
        );
        let source = GitHistorySource::new(repo).with_max_commits(50);
        let chunks = collect_ok(&source);
        assert_eq!(
            count_with(&chunks, "KEYHOGgit"),
            0,
            "a benign repo must not surface any planted sentinel"
        );
        assert_eq!(
            count_with(&chunks, "just some ordinary notes"),
            1,
            "the benign added line is scanned exactly once"
        );
    }

    #[test]
    fn history_walks_head_ancestry_without_unmerged_branch_commits() {
        let (_g, repo) = init_repo();
        commit(&repo, "base.txt", "main-base\n", "main base");
        let branch_status = Command::new("git")
            .args(["switch", "-c", "unmerged"])
            .current_dir(&repo)
            .status()
            .expect("create unmerged branch");
        assert!(branch_status.success());
        commit(
            &repo,
            "branch.env",
            &format!("secret={HISTORY_SECRET}\n"),
            "branch secret",
        );
        let branch_secret_commit = rev_parse(&repo, "HEAD");
        let main_status = Command::new("git")
            .args(["switch", "main"])
            .current_dir(&repo)
            .status()
            .expect("return to main");
        assert!(main_status.success());

        let main_chunks = collect_ok(&GitHistorySource::new(repo.clone()));
        assert_eq!(
            count_with(&main_chunks, HISTORY_SECRET),
            0,
            "an unmerged branch is outside main HEAD ancestry"
        );
        assert_eq!(count_with(&main_chunks, "main-base"), 1);

        let branch_status = Command::new("git")
            .args(["switch", "unmerged"])
            .current_dir(&repo)
            .status()
            .expect("select unmerged branch");
        assert!(branch_status.success());
        let branch_chunks = collect_ok(&GitHistorySource::new(repo));
        let branch_secret = chunk_with(&branch_chunks, HISTORY_SECRET)
            .expect("the same commit is scanned when it enters HEAD ancestry");
        assert_eq!(
            branch_secret.metadata.commit.as_deref(),
            Some(branch_secret_commit.as_str())
        );
    }

    // ---- diff: added-line-only, exact attribution -----------------------

    #[test]
    fn diff_new_file_secret_surfaces_with_base_line_zero_and_exact_path_and_commit() {
        let (_g, repo) = init_repo();
        let base = commit_returning_sha(&repo, "readme.txt", "hello world\n", "init");
        let head = commit_returning_sha(
            &repo,
            "secret.env",
            &format!("API_TOKEN={FILE_SECRET}\n"),
            "leak secret",
        );

        let source = GitDiffSource::new(repo, base.clone()).with_head_ref(head.clone());
        let chunks = collect_ok(&source);
        assert_eq!(
            chunks.len(),
            1,
            "only the newly-added file appears in the diff; the unchanged readme does not"
        );
        let chunk = &chunks[0];
        assert!(chunk.data.contains(FILE_SECRET), "planted secret surfaces");
        assert_eq!(chunk.metadata.source_type.as_ref(), "git-diff");
        assert_eq!(chunk.metadata.path.as_deref(), Some("secret.env"));
        assert_eq!(
            chunk.metadata.base_line, 0,
            "an added file's first line is absolute line 1 (base_line 0)"
        );
        assert_eq!(
            chunk.metadata.commit.as_deref(),
            Some(head.as_str()),
            "the diff chunk carries the head commit id"
        );
    }

    #[test]
    fn diff_added_line_reported_without_unchanged_context() {
        // Appending one line to an existing file: the diff must report ONLY the
        // new line, never the unchanged surrounding context.
        let (_g, repo) = init_repo();
        let base = commit_returning_sha(
            &repo,
            "creds.txt",
            "user=admin\npassword=placeholder\n",
            "init creds",
        );
        let head = commit_returning_sha(
            &repo,
            "creds.txt",
            &format!("user=admin\npassword=placeholder\n{ADDED_SECRET}\n"),
            "leak key",
        );

        let source = GitDiffSource::new(repo, base).with_head_ref(head);
        let chunks = collect_ok(&source);
        let chunk = chunk_with(&chunks, ADDED_SECRET).expect("the added secret line surfaces");
        assert!(
            !chunk.data.contains("user=admin"),
            "unchanged context line must not be re-reported by the diff source"
        );
        assert!(
            !chunk.data.contains("password=placeholder"),
            "unchanged context line must not be re-reported by the diff source"
        );
    }

    #[test]
    fn diff_added_secret_line_data_equals_trimmed_added_lines() {
        // Exact bytes: a two-line new file yields a chunk whose data is precisely
        // the two added lines joined by the interior newline, trimmed of the
        // trailing newline.
        let (_g, repo) = init_repo();
        let base = commit_returning_sha(&repo, "readme.txt", "hello\n", "init");
        let head = commit_returning_sha(&repo, "multi.env", "K1=aaaa\nK2=bbbb\n", "add multi");

        let source = GitDiffSource::new(repo, base).with_head_ref(head);
        let chunks = collect_ok(&source);
        assert_eq!(chunks.len(), 1, "exactly the one added file");
        // `&*` derefs SensitiveString to &str for a `&str == &str` comparison.
        assert_eq!(
            &*chunks[0].data, "K1=aaaa\nK2=bbbb",
            "chunk data is the added lines joined by the interior newline, trailing newline trimmed"
        );
        assert_eq!(chunks[0].metadata.base_line, 0);
    }

    #[test]
    fn diff_chunk_carries_head_commit_author_and_date_metadata() {
        let (_g, repo) = init_repo();
        let base = commit_returning_sha(&repo, "readme.txt", "hello\n", "init");
        let head = commit_returning_sha(
            &repo,
            "leak.env",
            &format!("KEY={FILE_SECRET}\n"),
            "leak env",
        );
        let expected_date = author_date_iso(&repo, &head);

        let source = GitDiffSource::new(repo, base).with_head_ref(head.clone());
        let chunks = collect_ok(&source);
        let chunk = chunk_with(&chunks, FILE_SECRET).expect("secret chunk");
        assert_eq!(
            chunk.metadata.author.as_deref(),
            Some(DIFF_AUTHOR),
            "git-diff author is the bare `%an` name (no email)"
        );
        assert_eq!(
            chunk.metadata.date.as_deref(),
            Some(expected_date.as_str()),
            "git-diff date equals the head commit's %aI author date"
        );
        assert_eq!(chunk.metadata.commit.as_deref(), Some(head.as_str()));
    }

    #[test]
    fn diff_range_across_two_commits_surfaces_each_added_file() {
        // A base..head range spanning two commits must surface every file added
        // across the range, each as its own chunk with its own path.
        let (_g, repo) = init_repo();
        let base = commit_returning_sha(&repo, "readme.txt", "hello\n", "init");
        commit(&repo, "a.env", "AKEY=aaaaaaaa\n", "add a");
        let head = commit_returning_sha(&repo, "b.env", "BKEY=bbbbbbbb\n", "add b");

        let source = GitDiffSource::new(repo, base).with_head_ref(head);
        let chunks = collect_ok(&source);
        let mut paths: Vec<&str> = chunks
            .iter()
            .filter_map(|c| c.metadata.path.as_deref())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec!["a.env", "b.env"],
            "both files added across the range surface as separate chunks"
        );
        assert_eq!(chunks.len(), 2, "exactly two added files, two chunks");
    }

    // ---- diff: negative twins (zero added lines) ------------------------

    #[test]
    fn diff_clean_identical_refs_yields_zero_chunks() {
        // Diffing a commit against itself: no added lines exist, so zero chunks.
        let (_g, repo) = init_repo();
        let sha = commit_returning_sha(&repo, "readme.txt", "hello\n", "init");
        let source = GitDiffSource::new(repo, sha.clone()).with_head_ref(sha);
        let chunks = collect_ok(&source);
        assert_eq!(
            chunks.len(),
            0,
            "a diff of a commit against itself has no added lines"
        );
    }

    #[test]
    fn diff_deletion_only_yields_zero_added_chunks() {
        // Removing a line contributes only a `-` line, never a `+` line, so a
        // deletion-only change must produce zero added-line chunks.
        let (_g, repo) = init_repo();
        let base = commit_returning_sha(&repo, "data.txt", "keep\nremoveme\n", "init");
        let head = commit_returning_sha(&repo, "data.txt", "keep\n", "delete a line");
        let source = GitDiffSource::new(repo, base).with_head_ref(head);
        let chunks = collect_ok(&source);
        assert_eq!(
            chunks.len(),
            0,
            "a pure deletion adds no lines, so the diff source emits no chunks"
        );
    }
}

#[cfg(not(feature = "git"))]
#[test]
fn git_history_diff_regression_requires_git_feature() {
    assert!(
        !cfg!(feature = "git"),
        "this lock only runs with the git feature"
    );
}
