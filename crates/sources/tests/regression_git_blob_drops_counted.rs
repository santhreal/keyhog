//! LANE sources-deep Law-10 regression: a git blob the history source DROPS
//! (over the per-blob `MAX_GIT_BLOB_BYTES` cap, a true-binary blob that carries
//! no grep-able credential, or the aggregate history source cap) must be COUNTED in the shared
//! `skip_counts()` so a "0 findings --git" run is not mistaken for full history
//! coverage — never a silent `let Ok(..) else { continue }` / `continue`.
//!
//! Before the fix `stream_git_blobs` dropped:
//!   * an over-cap blob (`header.size() > MAX_GIT_BLOB_BYTES`) with a bare
//!     `continue` (no counter), and
//!   * a binary blob (`decode_git_blob -> None`) with a bare `continue`,
//! so both vanished from coverage with no operator-visible signal. The fix
//! routes the over-cap drop to `SKIPPED_OVER_MAX_SIZE` and the binary drop to
//! `SKIPPED_BINARY` (the same CLI-surfaced categories the filesystem walker
//! uses) and logs each at `warn!`. This test pins the exact counter deltas by
//! driving the REAL `GitSource::chunks()` production path over a git repo built
//! with the system `git` binary.
//!
//! Own test binary: the `SKIPPED_*` counters are process-global atomics, so a
//! dedicated binary keeps the baseline isolated from the filesystem tests that
//! share them.

#![cfg(feature = "git")]

mod support;

use keyhog_sources::testing::{SourceTestApi, TestApi};
use std::path::Path;
use std::process::Command;
use std::sync::{Mutex, MutexGuard};
use support::split_chunk_results;

use keyhog_core::Source;
use keyhog_sources::{skip_counts, GitDiffSource, GitHistorySource, GitSource};

/// `MAX_GIT_BLOB_BYTES` from `git/source.rs`.
const MAX_GIT_BLOB_BYTES: usize = 10 * 1024 * 1024;
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn counter_guard() -> MutexGuard<'static, ()> {
    COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_repo(repo: &Path) {
    git(repo, &["init", "-b", "main"]);
    git(repo, &["config", "user.email", "drops@test.example"]);
    git(repo, &["config", "user.name", "Drop Regression"]);
}

/// An over-cap git blob (> 10 MiB) is dropped from the history scan and counted
/// as over-max-size, alongside a small text blob that IS scanned.
#[test]
fn oversized_git_blob_is_counted_over_max_size() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    init_repo(repo);

    // A small text blob that must be scanned (one chunk, recognizable content).
    std::fs::write(
        repo.join("small.txt"),
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", // keyhog:ignore detector=aws-access-key (synthetic test fixture)
    )
    .expect("write small blob");

    // An over-cap blob: > MAX_GIT_BLOB_BYTES of printable text so it is NOT
    // binary (it must hit the SIZE gate, not the binary gate). The leading
    // marker would be a finding if it were scanned — proving it is dropped.
    let mut big = String::with_capacity(MAX_GIT_BLOB_BYTES + 4096);
    big.push_str("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"); // keyhog:ignore detector=aws-access-key (synthetic test fixture)
    while big.len() <= MAX_GIT_BLOB_BYTES + 1024 {
        big.push_str("padding-line-no-secret-here aaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
    }
    assert!(
        big.len() > MAX_GIT_BLOB_BYTES,
        "fixture must exceed the per-blob cap"
    );
    std::fs::write(repo.join("huge.txt"), &big).expect("write big blob");

    git(repo, &["add", "."]);
    git(repo, &["commit", "-m", "small text + over-cap text blob"]);

    let chunks: Vec<String> = GitSource::new(repo.to_path_buf())
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .into_iter()
        .map(|c| c.data.as_ref().to_string())
        .collect();

    // The small blob is scanned exactly once; the huge blob never appears.
    let with_key = chunks
        .iter()
        .filter(|c| c.contains("AKIAIOSFODNN7EXAMPLE")) // keyhog:ignore detector=aws-access-key (synthetic test fixture)
        .count();
    assert_eq!(
        with_key, 1,
        "only the small blob (one occurrence of the key) must be scanned; the \
         over-cap blob's identical leading key must NOT appear. got chunks: {chunks:?}"
    );

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "the over-cap git blob MUST bump SKIPPED_OVER_MAX_SIZE exactly once (Law 10)"
    );
}

/// A true-binary git blob (recognized magic header) is dropped from the history
/// scan and counted as binary — the history analogue of the filesystem binary
/// skip — never a silent `continue`.
#[test]
fn binary_git_blob_is_counted_binary() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    init_repo(repo);

    // An ELF-magic binary blob: `decode_git_blob` recognizes the `\x7fELF`
    // header and returns None (true binary, no grep-able credential).
    let mut elf = vec![0x7f, b'E', b'L', b'F'];
    elf.extend_from_slice(&[0u8; 256]);
    std::fs::write(repo.join("app.bin"), &elf).expect("write binary blob");

    // A plain text blob so the commit is non-empty and the scan still runs.
    std::fs::write(repo.join("readme.txt"), "nothing secret here\n").expect("write text blob");

    git(repo, &["add", "."]);
    git(repo, &["commit", "-m", "binary + text"]);

    let _chunks: Vec<_> = GitSource::new(repo.to_path_buf())
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "the ELF-magic binary git blob MUST bump SKIPPED_BINARY exactly once (Law 10)"
    );
    assert_eq!(
        after.over_max_size - before.over_max_size,
        0,
        "a binary git blob must NOT be miscounted as an over-size skip"
    );
}

/// A tracked binary-file change represented by `git diff` as a binary patch is
/// still an unscanned input and must increment binary skip telemetry.
#[test]
fn tracked_binary_git_diff_patch_is_counted_binary() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    init_repo(repo);

    let mut base = vec![0x7f, b'E', b'L', b'F', 0];
    base.extend_from_slice(&[1u8; 512]);
    std::fs::write(repo.join("app.bin"), &base).expect("write base binary");
    git(repo, &["add", "app.bin"]);
    git(repo, &["commit", "-m", "base binary"]);

    let mut changed = vec![0x7f, b'E', b'L', b'F', 0];
    changed.extend_from_slice(&[2u8; 512]);
    std::fs::write(repo.join("app.bin"), &changed).expect("write changed binary");

    let chunks: Vec<_> = GitDiffSource::new(repo.to_path_buf(), "HEAD")
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        chunks.is_empty(),
        "binary-only tracked git-diff patch yields no scannable chunks"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "tracked binary git-diff patches MUST bump SKIPPED_BINARY exactly once"
    );
    assert_eq!(
        after.over_max_size - before.over_max_size,
        0,
        "tracked binary git-diff patches must not be miscounted as over-size skips"
    );
}

/// A binary-file commit represented by `git log -p` as a binary patch is still
/// an unscanned input and must increment binary skip telemetry.
#[test]
fn binary_git_history_patch_is_counted_binary() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    init_repo(repo);

    let mut elf = vec![0x7f, b'E', b'L', b'F', 0];
    elf.extend_from_slice(&[0u8; 512]);
    std::fs::write(repo.join("app.bin"), &elf).expect("write binary blob");
    git(repo, &["add", "app.bin"]);
    git(repo, &["commit", "-m", "binary commit"]);

    let chunks: Vec<_> = GitHistorySource::new(repo.to_path_buf())
        .with_max_commits(1)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        chunks.is_empty(),
        "binary-only git-history patch yields no scannable chunks"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "binary git-history patches MUST bump SKIPPED_BINARY exactly once"
    );
    assert_eq!(
        after.over_max_size - before.over_max_size,
        0,
        "binary git-history patches must not be miscounted as over-size skips"
    );
}

/// A true-binary untracked worktree file included by `--git-diff HEAD`
/// semantics is dropped from the diff scan and counted as binary, never a
/// silent `continue`.
#[test]
fn binary_untracked_git_diff_file_is_counted_binary() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    init_repo(repo);
    std::fs::write(repo.join("tracked.txt"), "tracked baseline\n").expect("write tracked");
    git(repo, &["add", "tracked.txt"]);
    git(repo, &["commit", "-m", "baseline"]);

    let mut elf = vec![0x7f, b'E', b'L', b'F'];
    elf.extend_from_slice(&[0u8; 512]);
    std::fs::write(repo.join("untracked.bin"), &elf).expect("write untracked binary");

    let chunks: Vec<_> = GitDiffSource::new(repo.to_path_buf(), "HEAD")
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        chunks.is_empty(),
        "binary-only untracked git-diff input yields no scannable chunks"
    );

    let after = skip_counts();
    assert_eq!(
        after.binary - before.binary,
        1,
        "the untracked ELF-magic git-diff file MUST bump SKIPPED_BINARY exactly once (Law 10)"
    );
}

/// An untracked worktree file that exceeds the git-diff byte cap is an
/// operator-visible source error and an over-size coverage event, not an
/// uncounted abort before diff chunks are emitted.
#[test]
fn oversized_untracked_git_diff_file_is_counted_over_max_size() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    init_repo(repo);
    std::fs::write(repo.join("tracked.txt"), "tracked baseline\n").expect("write tracked");
    git(repo, &["add", "tracked.txt"]);
    git(repo, &["commit", "-m", "baseline"]);

    std::fs::write(
        repo.join("untracked.txt"),
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", // keyhog:ignore detector=aws-access-key (synthetic over-cap fixture)
    )
    .expect("write oversized untracked file");

    let mut limits = keyhog_sources::SourceLimits::default();
    limits.git_blob_bytes = 12;

    let rows: Vec<_> = GitDiffSource::new(repo.to_path_buf(), "HEAD")
        .with_limits(limits)
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert!(
        ok.is_empty(),
        "over-cap untracked git-diff file must not emit chunks"
    );
    assert_eq!(
        errors.len(),
        1,
        "over-cap untracked git-diff file must surface one source error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("untracked.txt")
            && err.contains("exceeds git_blob_bytes limit")
            && err.contains("12"),
        "error should name the untracked file and cap, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.over_max_size - before.over_max_size,
        1,
        "the over-cap untracked git-diff file MUST bump SKIPPED_OVER_MAX_SIZE exactly once"
    );
    assert_eq!(
        after.binary - before.binary,
        0,
        "over-cap untracked git-diff file must not be miscounted as binary"
    );
}

/// The streamed `git ls-files --others -z` path must not grow one unbounded
/// path buffer if Git reports a hostile or corrupt path without a nearby NUL.
#[test]
fn overlong_untracked_git_diff_path_is_counted_source_truncated() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    init_repo(repo);
    std::fs::write(repo.join("tracked.txt"), "tracked baseline\n").expect("write tracked");
    git(repo, &["add", "tracked.txt"]);
    git(repo, &["commit", "-m", "baseline"]);
    std::fs::write(repo.join("abcdef.env"), "TOKEN=visible_if_not_capped\n")
        .expect("write long-path untracked file");

    let mut limits = keyhog_sources::SourceLimits::default();
    limits.git_line_bytes = 3;

    let rows: Vec<_> = GitDiffSource::new(repo.to_path_buf(), "HEAD")
        .with_limits(limits)
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert!(
        ok.is_empty(),
        "overlong untracked git-diff path must not emit chunks"
    );
    assert_eq!(
        errors.len(),
        1,
        "overlong untracked git-diff path must surface one source error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("longer than git_line_bytes") && err.contains("3"),
        "error should name the path cap, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "overlong untracked git-diff path MUST bump SOURCE_TRUNCATED exactly once"
    );
}

/// A blob skipped by the shared default-exclude policy is intentionally not
/// scanned, but it still has to reach the shared excluded coverage counter.
#[test]
fn default_excluded_git_blob_is_counted_excluded() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    init_repo(repo);
    std::fs::write(
        repo.join("Cargo.lock"),
        "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n", // keyhog:ignore detector=aws-access-key (synthetic excluded fixture)
    )
    .expect("write excluded lockfile");
    std::fs::write(repo.join("keep.env"), "KEEP=visible\n").expect("write keep");
    git(repo, &["add", "."]);
    git(repo, &["commit", "-m", "excluded lockfile"]);

    let chunks: Vec<_> = GitSource::new(repo.to_path_buf())
        .with_max_commits(1)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.metadata.path.as_deref() == Some("keep.env")),
        "non-excluded sibling must still be scanned"
    );
    assert!(
        !chunks
            .iter()
            .any(|chunk| chunk.metadata.path.as_deref() == Some("Cargo.lock")),
        "default-excluded Cargo.lock must not be emitted"
    );

    let after = skip_counts();
    assert_eq!(
        after.excluded - before.excluded,
        1,
        "the default-excluded Git blob MUST bump SKIPPED_EXCLUDED exactly once"
    );
}

/// Aggregate history caps stop the source before all remaining blobs are
/// exhausted. That is a source-level partial-coverage gap, not a clean end of
/// history and not a per-file size skip.
#[test]
fn aggregate_git_history_cap_is_counted_source_truncated() {
    let _guard = counter_guard();
    TestApi.reset_skip_counters();
    let before = skip_counts();

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path();
    init_repo(repo);
    std::fs::write(repo.join("first.txt"), "FIRST=visible\n").expect("write first");
    std::fs::write(repo.join("second.txt"), "SECOND=not reached\n").expect("write second");
    git(repo, &["add", "."]);
    git(repo, &["commit", "-m", "two chunks"]);

    let mut limits = keyhog_sources::SourceLimits::default();
    limits.git_chunk_count = 1;

    let rows: Vec<_> = GitSource::new(repo.to_path_buf())
        .with_limits(limits)
        .chunks()
        .collect();
    let (ok, errors) = split_chunk_results(&rows);
    assert_eq!(
        ok.len(),
        1,
        "the first Git history chunk should still be scanned before the cap"
    );
    assert_eq!(
        errors.len(),
        1,
        "aggregate Git cap must surface one source error"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("git history source was truncated")
            && err.contains("remaining blobs were not scanned"),
        "error should describe partial Git history coverage, got {err}"
    );

    let after = skip_counts();
    assert_eq!(
        after.source_truncated - before.source_truncated,
        1,
        "aggregate Git cap MUST bump SOURCE_TRUNCATED exactly once"
    );
    assert_eq!(
        after.over_max_size - before.over_max_size,
        0,
        "aggregate Git cap is not a per-blob/per-file over-size skip"
    );
}
