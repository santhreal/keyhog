//! Source-instrumentation suite for the git adapters (worktree/history blobs,
//! diff, log history, staged index).
//!
//! WHY: each git adapter acquires through its own child-process plumbing and
//! object reads. These tests pin the exact stage span counts and real chunk
//! byte totals per adapter on tiny synthetic repositories so a refactor that
//! drops the acquisition span, the enumeration walk span, or the per-chunk
//! accounting fails with the adapter named.

#![cfg(feature = "git")]

mod support;

use keyhog_core::Source;
use keyhog_profile::Stage;
use keyhog_sources::{GitDiffSource, GitHistorySource, GitSource, GitStagedSource};
use support::profile::{run_with_profile, stage_calls};

/// `GitSource` (reachable history blobs) records one acquisition, tree-walk
/// and blob-read spans, and one input unit per emitted blob chunk.
///
/// Locks out: losing the per-chunk unit/byte accounting when the streaming
/// iterator changes shape (it is the only place real blob counts are known).
#[test]
fn git_source_records_acquire_walk_read_and_blob_totals() {
    let (_temp, repo) = support::git::init_repo();
    let body = "token = \"AKIAGITFIXTURE000001\"\n";
    support::git::commit(&repo, "config.txt", body, "add config");

    let (profile, rows) =
        run_with_profile(|| GitSource::new(repo.clone()).chunks().collect::<Vec<_>>());

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy git fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "one committed blob yields one chunk: {rows:?}"
    );
    assert!(chunks[0].data.contains("AKIAGITFIXTURE000001"));

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert!(
        stage_calls(&profile, Stage::SourceWalk) >= 1,
        "the commit tree traversal records a walk span"
    );
    assert!(
        stage_calls(&profile, Stage::SourceRead) >= 1,
        "the blob batch decode records a read span"
    );
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, body.len() as u64);
}

/// `GitHistorySource` (git log -p) records one acquisition, one enumeration
/// span per streamed hunk, and one unit per emitted hunk chunk.
///
/// Locks out: the log parser losing its walk span when hunk draining changes.
#[test]
fn git_history_records_enumeration_and_hunk_totals() {
    let (_temp, repo) = support::git::init_repo();
    let first = "first line\n";
    let second = "first line\nsecond line\n";
    support::git::commit(&repo, "notes.txt", first, "first commit");
    support::git::commit(&repo, "notes.txt", second, "second commit");

    let (profile, rows) = run_with_profile(|| {
        GitHistorySource::new(repo.clone())
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy git fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        2,
        "two commits yield one added-line hunk each: {rows:?}"
    );

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert!(
        stage_calls(&profile, Stage::SourceWalk) >= 2,
        "each streamed hunk passes through the enumeration loop"
    );
    let expected_bytes: u64 = chunks.iter().map(|chunk| chunk.data.len() as u64).sum();
    assert_eq!(profile.input_units, 2);
    assert_eq!(profile.input_bytes, expected_bytes);
    assert!(expected_bytes > 0);
}

/// `GitDiffSource` against HEAD with one modified tracked file records one
/// acquisition, enumeration spans, and the emitted hunk as input.
///
/// Locks out: the diff adapter dropping its acquisition span when refs or the
/// diff child spawn move.
#[test]
fn git_diff_records_acquire_and_hunk_totals() {
    let (_temp, repo) = support::git::init_repo();
    support::git::commit(&repo, "app.txt", "line one\n", "base commit");
    std::fs::write(repo.join("app.txt"), "line one\nline two\n").expect("modify fixture");

    let (profile, rows) = run_with_profile(|| {
        GitDiffSource::new(repo.clone(), "HEAD")
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy git fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "one modified file yields one hunk: {rows:?}"
    );
    assert!(chunks[0].data.contains("line two"));

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert!(stage_calls(&profile, Stage::SourceWalk) >= 1);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, chunks[0].data.len() as u64);
}

/// `GitStagedSource` with one staged new file records one acquisition, index
/// enumeration, a blob object read, and the staged blob as input.
///
/// Locks out: the staged index iterator losing its enumeration or object-read
/// spans when the raw-diff record parsing changes.
#[test]
fn git_staged_records_enumeration_read_and_blob_totals() {
    let (_temp, repo) = support::git::init_repo();
    support::git::commit(&repo, "tracked.txt", "tracked\n", "base commit");
    let staged_body = "staged secret = \"AKIASTAGEDFIXTURE01\"\n";
    std::fs::write(repo.join("staged.txt"), staged_body).expect("write staged fixture");
    let add = std::process::Command::new("git")
        .args(["add", "staged.txt"])
        .current_dir(&repo)
        .output()
        .expect("git add");
    assert!(add.status.success(), "git add failed: {add:?}");

    let (profile, rows) = run_with_profile(|| {
        GitStagedSource::try_new(repo.clone())
            .expect("staged fixture present")
            .chunks()
            .collect::<Vec<_>>()
    });

    let (chunks, errors) = support::split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a healthy git fixture must not report coverage errors: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "one staged file yields one chunk: {rows:?}"
    );
    assert!(chunks[0].data.contains("AKIASTAGEDFIXTURE01"));

    assert_eq!(stage_calls(&profile, Stage::SourceAcquire), 1);
    assert!(stage_calls(&profile, Stage::SourceWalk) >= 1);
    assert!(stage_calls(&profile, Stage::SourceRead) >= 1);
    assert_eq!(profile.input_units, 1);
    assert_eq!(profile.input_bytes, staged_body.len() as u64);
}
