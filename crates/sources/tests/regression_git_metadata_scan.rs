//! Regression lock for the git **tag / history metadata** scan path
//! (`GitSource` + `GitHistorySource`).
//!
//! A credential can leak in three distinct places in a repository:
//!   1. inside a **file blob** (the obvious case),
//!   2. inside an **annotated tag message** (release notes, "reminder" tags), and
//!   3. inside a **commit message**.
//!
//! `GitSource` scans reachable file blobs (labelled `git/head` when the blob is
//! still live in HEAD, `git/history` when it only survives in an older commit)
//! and every reachable *annotated* tag's message (`git/tag`). These tests build
//! a real temp repository for each case and assert the EXACT surfaced chunk:
//! its `source_type`, its `commit`/`author`/`path` metadata, and that its bytes
//! contain the planted secret. A clean repo is asserted to yield an exact chunk
//! count so a coverage regression that drops a whole category is caught, not
//! masked by a `!is_empty()` check.
//!
//! Two tests document a genuine coverage GAP: a secret planted ONLY in a commit
//! *message* (not in any file or tag) surfaces through NEITHER git source,
//! because `GitSource` walks trees/blobs and `GitHistorySource`'s
//! `--format=commit %H%nAuthor:…%nDate:…` never emits the message body. They
//! assert the real current behaviour (zero chunks carry that sentinel) so the
//! day the gap is closed, the lock flips and forces this file to be updated.

#![cfg(unix)]

mod support;

#[cfg(feature = "git")]
mod git_metadata {
    use super::support::git::{commit, init_repo};
    use super::support::split_chunk_results;
    use keyhog_core::{Chunk, Source};
    use keyhog_sources::{GitHistorySource, GitSource};
    use std::path::Path;
    use std::process::Command;

    // Sentinels are deliberately unique, non-overlapping strings so a chunk that
    // contains one could only have come from the place it was planted.
    const FILE_SECRET: &str = "KEYHOGgitFILEsecret_AKIA0000FILE0000BLOB";
    const TAG_SECRET: &str = "KEYHOGgitTAGsecret_AKIA1111TAG1111MSG";
    const TAG_SECRET_2: &str = "KEYHOGgitTAGsecret_AKIA2222TAG2222MSG";
    const COMMIT_MSG_SECRET: &str = "KEYHOGgitCOMMITMSGsecret_AKIA3333MESSAGE";
    const HISTORY_SECRET: &str = "KEYHOGgitHISTORYsecret_AKIA4444REMOVED44";

    /// Create an annotated tag whose message body carries `message`.
    fn annotated_tag(repo: &Path, name: &str, message: &str) {
        let out = Command::new("git")
            .args(["tag", "-a", name, "-m", message])
            .current_dir(repo)
            .output()
            .expect("git tag -a");
        assert!(out.status.success(), "git tag -a failed: {out:?}");
    }

    /// Create a lightweight tag (no tag object, points straight at the commit).
    fn lightweight_tag(repo: &Path, name: &str) {
        let out = Command::new("git")
            .args(["tag", name])
            .current_dir(repo)
            .output()
            .expect("git tag");
        assert!(out.status.success(), "git tag failed: {out:?}");
    }

    /// Collect `GitSource` chunks, asserting the fixture emits no `SourceError`.
    fn git_chunks(repo: &Path) -> Vec<Chunk> {
        let source = GitSource::new(repo.to_path_buf()).with_max_commits(50);
        let rows: Vec<_> = source.chunks().collect();
        let (chunk_refs, errors) = split_chunk_results(&rows);
        assert!(
            errors.is_empty(),
            "clean fixture repo must not emit SourceError rows: {errors:?}"
        );
        chunk_refs.into_iter().cloned().collect()
    }

    /// Collect `GitHistorySource` chunks, asserting no `SourceError`.
    fn history_chunks(repo: &Path) -> Vec<Chunk> {
        let source = GitHistorySource::new(repo.to_path_buf()).with_max_commits(50);
        let rows: Vec<_> = source.chunks().collect();
        let (chunk_refs, errors) = split_chunk_results(&rows);
        assert!(
            errors.is_empty(),
            "clean fixture repo must not emit SourceError rows: {errors:?}"
        );
        chunk_refs.into_iter().cloned().collect()
    }

    fn with_source_type<'a>(chunks: &'a [Chunk], source_type: &str) -> Vec<&'a Chunk> {
        chunks
            .iter()
            .filter(|c| c.metadata.source_type.as_ref() == source_type)
            .collect()
    }

    fn chunk_containing<'a>(chunks: &'a [Chunk], needle: &str) -> Option<&'a Chunk> {
        chunks.iter().find(|c| c.data.contains(needle))
    }

    // ---- source identity -------------------------------------------------

    #[test]
    fn git_source_names_are_stable() {
        let (_g, repo) = init_repo();
        assert_eq!(GitSource::new(repo.clone()).name(), "git");
        assert_eq!(GitHistorySource::new(repo).name(), "git-history");
    }

    // ---- file blob -> git/head ------------------------------------------

    #[test]
    fn file_secret_surfaces_as_git_head_chunk() {
        let (_g, repo) = init_repo();
        commit(
            &repo,
            "config.env",
            &format!("api_key={FILE_SECRET}\n"),
            "add config",
        );
        let chunks = git_chunks(&repo);
        let heads = with_source_type(&chunks, "git/head");
        let chunk = heads
            .iter()
            .find(|c| c.data.contains(FILE_SECRET))
            .expect("a git/head chunk must carry the committed file secret");
        assert_eq!(chunk.metadata.source_type.as_ref(), "git/head");
        assert_eq!(chunk.metadata.path.as_deref(), Some("config.env"));
        assert!(
            chunk.data.contains(FILE_SECRET),
            "file secret bytes preserved"
        );
        // The secret is live in HEAD, so it must NOT be labelled history.
        assert!(
            with_source_type(&chunks, "git/history")
                .iter()
                .all(|c| !c.data.contains(FILE_SECRET)),
            "a live-in-HEAD secret must not be downgraded to git/history"
        );
    }

    #[test]
    fn git_head_chunk_carries_commit_and_author_metadata() {
        let (_g, repo) = init_repo();
        commit(&repo, "secret.txt", &format!("{FILE_SECRET}\n"), "leak");
        let chunks = git_chunks(&repo);
        let chunk = with_source_type(&chunks, "git/head")
            .into_iter()
            .find(|c| c.data.contains(FILE_SECRET))
            .expect("git/head chunk");
        let commit_id = chunk.metadata.commit.as_deref().expect("commit id present");
        assert_eq!(commit_id.len(), 40, "full SHA-1 commit id");
        assert!(
            commit_id.chars().all(|c| c.is_ascii_hexdigit()),
            "commit id is lowercase hex, got {commit_id:?}"
        );
        // GitSource author is the raw commit author *name* (no email).
        assert_eq!(chunk.metadata.author.as_deref(), Some("LR1 A5"));
        assert!(
            chunk.metadata.date.is_none(),
            "GitSource blob chunks carry no date"
        );
    }

    // ---- annotated tag message -> git/tag -------------------------------

    #[test]
    fn annotated_tag_message_secret_surfaces_as_git_tag_chunk() {
        let (_g, repo) = init_repo();
        commit(&repo, "app.py", "print('ok')\n", "init");
        annotated_tag(&repo, "v1.0", &format!("release notes {TAG_SECRET}"));
        let chunks = git_chunks(&repo);
        let tags = with_source_type(&chunks, "git/tag");
        assert_eq!(
            tags.len(),
            1,
            "exactly one annotated tag => one git/tag chunk"
        );
        let tag = tags[0];
        assert!(tag.data.contains(TAG_SECRET), "tag message bytes preserved");
        assert!(
            tag.data.contains("release notes"),
            "surrounding message text preserved"
        );
        // The tag secret must NOT leak into a file-blob chunk.
        assert!(
            with_source_type(&chunks, "git/head")
                .iter()
                .all(|c| !c.data.contains(TAG_SECRET)),
            "tag-only secret must not appear in a git/head file chunk"
        );
    }

    #[test]
    fn git_tag_chunk_path_is_full_refname_and_commit_is_none() {
        let (_g, repo) = init_repo();
        commit(&repo, "a.txt", "x\n", "init");
        annotated_tag(&repo, "v2.3.4", &format!("notes {TAG_SECRET}"));
        let chunks = git_chunks(&repo);
        let tag = with_source_type(&chunks, "git/tag")[0];
        assert_eq!(
            tag.metadata.path.as_deref(),
            Some("refs/tags/v2.3.4"),
            "git/tag path is the full ref name"
        );
        assert!(
            tag.metadata.commit.is_none(),
            "a tag message chunk has no owning commit id; got {:?}",
            tag.metadata.commit
        );
    }

    #[test]
    fn git_tag_chunk_author_is_tagger_and_size_bytes_match() {
        let (_g, repo) = init_repo();
        commit(&repo, "a.txt", "x\n", "init");
        let message = format!("release {TAG_SECRET}");
        annotated_tag(&repo, "v1.0", &message);
        let chunks = git_chunks(&repo);
        let tag = with_source_type(&chunks, "git/tag")[0];
        assert_eq!(
            tag.metadata.author.as_deref(),
            Some("LR1 A5"),
            "git/tag author is the tagger name"
        );
        let size = tag
            .metadata
            .size_bytes
            .expect("tag chunk records message size");
        assert_eq!(
            size,
            tag.data.as_bytes().len() as u64,
            "size_bytes equals the ASCII tag-message byte length"
        );
    }

    #[test]
    fn lightweight_tag_is_not_scanned_as_tag_message() {
        // A lightweight tag has no tag object (for-each-ref reports objecttype
        // `commit`), so it must produce NO git/tag chunk even though its name is
        // in refs/tags. The secret lives only in the lightweight tag's *name*
        // context here; there is no message to scan.
        let (_g, repo) = init_repo();
        commit(&repo, "a.txt", "x\n", "init");
        lightweight_tag(&repo, "lw-release");
        let chunks = git_chunks(&repo);
        assert_eq!(
            with_source_type(&chunks, "git/tag").len(),
            0,
            "a lightweight tag must not produce a git/tag message chunk"
        );
    }

    #[test]
    fn multiple_annotated_tags_each_surface_as_tag_chunks() {
        let (_g, repo) = init_repo();
        commit(&repo, "a.txt", "x\n", "init");
        annotated_tag(&repo, "v1.0", &format!("first {TAG_SECRET}"));
        annotated_tag(&repo, "v2.0", &format!("second {TAG_SECRET_2}"));
        let chunks = git_chunks(&repo);
        let tags = with_source_type(&chunks, "git/tag");
        assert_eq!(tags.len(), 2, "two annotated tags => two git/tag chunks");
        assert!(
            tags.iter().any(|c| c.data.contains(TAG_SECRET)),
            "first tag secret surfaces"
        );
        assert!(
            tags.iter().any(|c| c.data.contains(TAG_SECRET_2)),
            "second tag secret surfaces"
        );
    }

    #[test]
    fn multiline_tag_message_bytes_preserved() {
        let (_g, repo) = init_repo();
        commit(&repo, "a.txt", "x\n", "init");
        let message = format!("release v9\nembedded: {TAG_SECRET}\ntrailing line");
        annotated_tag(&repo, "v9.0", &message);
        let chunks = git_chunks(&repo);
        let tag = with_source_type(&chunks, "git/tag")[0];
        assert!(
            tag.data.contains("release v9"),
            "first message line preserved"
        );
        assert!(
            tag.data.contains(TAG_SECRET),
            "interior secret line preserved"
        );
        assert!(
            tag.data.contains("trailing line"),
            "last message line preserved"
        );
        assert!(
            tag.data.matches('\n').count() >= 2,
            "interior newlines of a multi-line tag message survive; got {:?}",
            tag.data
        );
    }

    #[test]
    fn benign_annotated_tag_has_no_secret_marker() {
        let (_g, repo) = init_repo();
        commit(&repo, "a.txt", "x\n", "init");
        annotated_tag(&repo, "v1.0", "routine release, nothing sensitive");
        let chunks = git_chunks(&repo);
        let tags = with_source_type(&chunks, "git/tag");
        assert_eq!(
            tags.len(),
            1,
            "the benign annotated tag still yields one chunk"
        );
        assert!(
            tags[0].data.contains("routine release"),
            "benign message text is scanned verbatim"
        );
        assert!(
            !tags[0].data.contains("KEYHOG"),
            "a benign tag must not fabricate a secret sentinel"
        );
    }

    // ---- history labelling ----------------------------------------------

    #[test]
    fn secret_removed_from_head_surfaces_as_git_history_via_git_source() {
        // Classic "we rotated it out of HEAD" case: the secret is gone from the
        // current tree but survives in an older commit's blob, so GitSource must
        // surface it and label it git/history (a still-real, lower-urgency leak).
        let (_g, repo) = init_repo();
        commit(
            &repo,
            "config.txt",
            &format!("token = {HISTORY_SECRET}\n"),
            "add token",
        );
        commit(&repo, "config.txt", "token = rotated\n", "rotate token");
        let chunks = git_chunks(&repo);
        let history = with_source_type(&chunks, "git/history");
        let chunk = history
            .iter()
            .find(|c| c.data.contains(HISTORY_SECRET))
            .expect("removed-from-HEAD secret must surface as a git/history chunk");
        assert_eq!(chunk.metadata.source_type.as_ref(), "git/history");
        assert_eq!(chunk.metadata.path.as_deref(), Some("config.txt"));
        assert_eq!(
            chunk.metadata.commit.as_deref().map(str::len),
            Some(40),
            "history chunk carries the owning commit id"
        );
        // The current HEAD content must NOT still contain the removed secret.
        assert!(
            with_source_type(&chunks, "git/head")
                .iter()
                .all(|c| !c.data.contains(HISTORY_SECRET)),
            "rotated-out secret must not be labelled git/head"
        );
    }

    // ---- commit-message coverage GAP ------------------------------------

    #[test]
    fn commit_message_only_secret_not_scanned_by_git_source() {
        // GitSource walks trees/blobs + annotated tag objects only. A secret that
        // lives ONLY in a commit message (not in any file or tag) is NOT reached.
        // This asserts the real current behaviour so the gap is visible and the
        // lock flips the day commit-message scanning is added.
        let (_g, repo) = init_repo();
        commit(
            &repo,
            "notes.txt",
            "just some notes\n",
            &format!("chore: rotate {COMMIT_MSG_SECRET}"),
        );
        let chunks = git_chunks(&repo);
        assert_eq!(
            chunks
                .iter()
                .filter(|c| c.data.contains(COMMIT_MSG_SECRET))
                .count(),
            0,
            "GitSource does not currently scan commit messages (coverage gap)"
        );
    }

    #[test]
    fn commit_message_only_secret_not_scanned_by_git_history_source() {
        // GitHistorySource's log format is `commit %H / Author / Date` + patch;
        // the message body is never emitted, so a commit-message-only secret is
        // invisible here too.
        let (_g, repo) = init_repo();
        commit(
            &repo,
            "notes.txt",
            "just some notes\n",
            &format!("chore: rotate {COMMIT_MSG_SECRET}"),
        );
        let chunks = history_chunks(&repo);
        assert_eq!(
            chunks
                .iter()
                .filter(|c| c.data.contains(COMMIT_MSG_SECRET))
                .count(),
            0,
            "GitHistorySource does not currently scan commit messages (coverage gap)"
        );
    }

    // ---- exact counts on clean repos ------------------------------------

    #[test]
    fn clean_single_file_repo_yields_exactly_one_head_chunk() {
        let (_g, repo) = init_repo();
        commit(&repo, "readme.txt", "hello world\n", "init");
        let chunks = git_chunks(&repo);
        assert_eq!(chunks.len(), 1, "one committed file => exactly one chunk");
        assert_eq!(chunks[0].metadata.source_type.as_ref(), "git/head");
        assert_eq!(chunks[0].metadata.path.as_deref(), Some("readme.txt"));
        assert!(chunks[0].data.contains("hello world"));
    }

    #[test]
    fn clean_two_file_repo_yields_exactly_two_head_chunks() {
        let (_g, repo) = init_repo();
        commit(&repo, "a.txt", "aaa\n", "add a");
        commit(&repo, "b.txt", "bbb\n", "add b");
        let chunks = git_chunks(&repo);
        let heads = with_source_type(&chunks, "git/head");
        assert_eq!(
            heads.len(),
            2,
            "two distinct live files => exactly two git/head chunks"
        );
        let mut paths: Vec<&str> = heads
            .iter()
            .filter_map(|c| c.metadata.path.as_deref())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            vec!["a.txt", "b.txt"],
            "both file paths surface, deduped"
        );
    }

    // ---- history source file coverage + metadata ------------------------

    #[test]
    fn git_history_source_yields_file_secret_with_commit_author_date() {
        let (_g, repo) = init_repo();
        commit(
            &repo,
            "creds.txt",
            &format!("secret={FILE_SECRET}\n"),
            "add creds",
        );
        let chunks = history_chunks(&repo);
        let chunk = chunk_containing(&chunks, FILE_SECRET)
            .expect("git-history must surface the added file secret");
        assert_eq!(chunk.metadata.source_type.as_ref(), "git-history");
        assert_eq!(chunk.metadata.path.as_deref(), Some("creds.txt"));
        let commit_id = chunk.metadata.commit.as_deref().expect("commit id");
        assert_eq!(commit_id.len(), 40, "full SHA-1 commit id");
        // GitHistorySource author includes the email (format `%an <%ae>`).
        assert_eq!(
            chunk.metadata.author.as_deref(),
            Some("LR1 A5 <a5@test.example>"),
            "git-history author is `name <email>`"
        );
        let date = chunk.metadata.date.as_deref().expect("commit date present");
        assert!(
            date.contains('T'),
            "ISO-strict date has a T separator, got {date:?}"
        );
        assert_eq!(
            &date[4..5],
            "-",
            "YYYY-MM-DD dash after the year, got {date:?}"
        );
        assert_eq!(
            &date[7..8],
            "-",
            "YYYY-MM-DD dash after the month, got {date:?}"
        );
    }
}

#[cfg(not(feature = "git"))]
#[test]
fn git_metadata_scan_requires_git_feature() {
    assert!(
        !cfg!(feature = "git"),
        "this lock only runs with the git feature"
    );
}
