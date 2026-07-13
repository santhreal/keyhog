//! Special-file + symlink safety matrix for the PUBLIC `FilesystemSource` scan
//! path (the general filesystem source, not the feature-gated `binary` source).
//!
//! A content scanner walks untrusted trees. Two contracts must hold for every
//! non-regular / symlinked entry it meets:
//!   1. It must NEVER block. A plain `open(O_RDONLY)` of a writer-less FIFO hangs
//!      forever; `open_file_safe`'s `O_NONBLOCK` makes the open return so the
//!      post-open `is_file()` fstat can refuse it. Every scan here runs inside a
//!      10s watchdog thread that FAILS the test if the read hangs.
//!   2. It must NEVER surface out-of-tree bytes. `follow_symlinks(false)` +
//!      codewalk's `is_file()` filter drop symlinks/FIFOs/sockets/devices at the
//!      walk, and the archive-symlink audit refuses link-swap of expandable
//!      containers (so a symlink target's secret must never reach a chunk).
//!
//! Two levels are exercised:
//!   * the read boundary via the `keyhog_sources::testing` facade
//!     (`read_file_safe_capped` / `read_file_mmap`) with EXACT `ErrorKind` /
//!     `errno` assertions, and
//!   * the full public `FilesystemSource::chunks()` scan over a temp-dir matrix
//!     with EXACT chunk counts, source-type strings, error text, and the
//!     `SkipCounts` snapshot.
//!
//! Every assertion checks a concrete value: an exact `ErrorKind`, an exact
//! `errno`, the exact returned bytes, the exact chunk count, the exact
//! `source_type` string, an exact substring of the refusal error, or the exact
//! `SkipCounts` snapshot (never a bare `is_ok()` / `!is_empty()`).

#![cfg(unix)]

mod support;

use keyhog_core::{Chunk, Source, SourceError};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource, SkipCounts};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use support::split_chunk_results;

/// A regular in-tree secret. Distinctive so absence/presence is unambiguous.
const IN_TREE_SECRET: &str = "AKIA_TESTSENTINEL_FILESYSTEM_MATRIX_001";
/// A secret that lives OUTSIDE any scanned tree, reachable only through a
/// symlink. It must NEVER appear in a scanned chunk.
const VICTIM_SECRET: &str = "VICTIM_OUT_OF_TREE_SECRET_9c3f01d7";

/// Run `f` on a worker thread and REQUIRE it to finish within 10s. A blocking
/// `open(O_RDONLY)` of a writer-less FIFO never returns, so this is the
/// regression guard proving the scan returns instead of hanging.
fn within_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(10)).expect(
        "the filesystem scan hung past 10s, a writer-less FIFO open without O_NONBLOCK blocks \
         forever; open_file_safe's O_NONBLOCK must make it return",
    )
}

/// Create a FIFO at `path` via `mkfifo(1)` (coreutils, present on every POSIX
/// host). Panics loudly if creation fails, a missing mkfifo is a misconfigured
/// test host, not a silent skip.
fn make_fifo(path: &Path) {
    let status = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .expect("spawn mkfifo");
    assert!(
        status.success(),
        "mkfifo failed to create {}",
        path.display()
    );
}

/// Collect every row `FilesystemSource::chunks()` yields for `root`.
fn scan_rows(root: PathBuf) -> Vec<Result<Chunk, SourceError>> {
    FilesystemSource::new(root).chunks().collect()
}

// ===========================================================================
// Read boundary (facade): exact ErrorKind / errno for each special-file class.
// ===========================================================================

#[test]
fn read_boundary_fifo_refused_with_invalid_input_and_no_hang() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe");
    make_fifo(&fifo);
    // A raw blocking open would never return; within_timeout fails on a hang.
    let probe = fifo.clone();
    let err = within_timeout(move || TestApi.read_file_safe_capped(&probe, 4096))
        .expect_err("a FIFO must be refused by the safe read boundary");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidInput,
        "a FIFO is opened via O_NONBLOCK then refused by the post-open is_file() fstat"
    );
    assert!(
        err.to_string().contains("non-regular"),
        "the refusal must name the cause; got {err}"
    );
}

#[test]
fn read_boundary_dev_null_refused_with_invalid_input() {
    assert!(
        Path::new("/dev/null").exists(),
        "/dev/null is missing on this host, cannot validate device refusal"
    );
    let err = TestApi
        .read_file_safe_capped(Path::new("/dev/null"), 4096)
        .expect_err("/dev/null (a char device) must be refused, not read as an empty file");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn read_boundary_unix_socket_refused_with_enxio() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    let err = TestApi
        .read_file_safe_capped(&sock, 4096)
        .expect_err("a unix-domain socket must be refused");
    // A socket is refused at the open(2) syscall itself (ENXIO), BEFORE the
    // post-open metadata guard runs (distinct errno from the FIFO/device path).
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENXIO),
        "opening a unix-domain socket path returns ENXIO"
    );
}

#[test]
fn read_boundary_symlink_refused_with_eloop_and_target_readable_directly() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real.txt");
    let body = format!("key = {IN_TREE_SECRET}\n");
    std::fs::write(&target, &body).unwrap();
    let link = dir.path().join("alias.txt");
    symlink(&target, &link).unwrap();

    // O_NOFOLLOW makes the open of the final symlink component fail with ELOOP,
    // so the link is never followed to its target.
    let err = TestApi
        .read_file_safe_capped(&link, 4096)
        .expect_err("O_NOFOLLOW must refuse the symlink final component");
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ELOOP),
        "O_NOFOLLOW open of a symlink final component returns ELOOP"
    );

    // The refusal is specifically about following the link: the REAL target,
    // named directly, still reads its exact bytes (recall preserved).
    let bytes = TestApi
        .read_file_safe_capped(&target, 4096)
        .expect("the real regular target must read fine when named directly");
    assert_eq!(bytes, body.as_bytes());
}

#[test]
fn read_boundary_regular_file_returns_exact_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config.env");
    let body = format!("token={IN_TREE_SECRET}\nnext=line\n");
    std::fs::write(&file, &body).unwrap();
    let bytes = TestApi
        .read_file_safe_capped(&file, 4096)
        .expect("a regular file must read");
    assert_eq!(
        bytes,
        body.as_bytes(),
        "the safe read must return the file's exact bytes unchanged"
    );
}

#[test]
fn read_mmap_facade_none_for_fifo_some_text_for_regular() {
    // `read_file_mmap` bumps the process-global Unreadable counter when it
    // refuses the FIFO, so hold the exclusive scan scope to serialize this
    // ungated bump against the counter-snapshot tests below.
    let _guard = TestApi.skip_counter_guard();
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe");
    make_fifo(&fifo);
    let probe = fifo.clone();
    let mmap_fifo = within_timeout(move || TestApi.read_file_mmap(&probe));
    assert_eq!(
        mmap_fifo, None,
        "read_file_mmap must skip (None) a FIFO, not block or map it"
    );

    let file = dir.path().join("plain.txt");
    let body = format!("secret {IN_TREE_SECRET} end");
    std::fs::write(&file, &body).unwrap();
    assert_eq!(
        TestApi.read_file_mmap(&file),
        Some(body.clone()),
        "read_file_mmap of a regular UTF-8 file returns its exact text"
    );
}

// ===========================================================================
// Full public FilesystemSource scan matrix.
// ===========================================================================

#[test]
fn scan_regular_file_yields_one_filesystem_chunk_with_secret() {
    let dir = tempfile::tempdir().unwrap();
    let body = format!("aws_secret = {IN_TREE_SECRET}\n");
    std::fs::write(dir.path().join("creds.txt"), &body).unwrap();

    let rows = scan_rows(dir.path().to_path_buf());
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a clean regular file must not error: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "exactly one chunk for the single small file"
    );
    let chunk = chunks[0];
    assert_eq!(
        chunk.metadata.source_type.as_ref(),
        "filesystem",
        "a plain-text filesystem file is delivered with the 'filesystem' source type"
    );
    assert_eq!(
        &*chunk.data,
        body.as_str(),
        "the chunk must carry the file's exact bytes to the scanner"
    );
    assert!(
        chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.ends_with("creds.txt")),
        "the chunk path must name the scanned file; got {:?}",
        chunk.metadata.path
    );
}

#[test]
fn scan_fifo_in_tree_returns_within_watchdog_and_yields_no_rows() {
    let dir = tempfile::tempdir().unwrap();
    make_fifo(&dir.path().join("pipe"));
    let root = dir.path().to_path_buf();
    // If the walk ever opened the FIFO with a blocking open, this hangs and the
    // watchdog fails the test.
    let rows = within_timeout(move || scan_rows(root));
    assert_eq!(
        rows.len(),
        0,
        "a FIFO is dropped at the walk (is_file()==false): no chunk, no error row"
    );
}

#[test]
fn scan_symlink_to_out_of_tree_secret_does_not_surface_it() {
    // The victim lives in a SEPARATE tree, reachable only through the link.
    let victim_dir = tempfile::tempdir().unwrap();
    let victim = victim_dir.path().join("victim_credentials");
    std::fs::write(&victim, format!("body {VICTIM_SECRET} more\n")).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let sibling_body = format!("in_tree = {IN_TREE_SECRET}\n");
    std::fs::write(dir.path().join("real.txt"), &sibling_body).unwrap();
    symlink(&victim, dir.path().join("alias.txt")).unwrap();

    let rows = scan_rows(dir.path().to_path_buf());
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a non-archive symlink is a silent walk-drop: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "only the regular sibling is scanned; the symlink is dropped at the walk"
    );
    assert!(
        chunks[0].data.contains(IN_TREE_SECRET),
        "the regular in-tree file must still be scanned (recall preserved)"
    );
    for chunk in &chunks {
        assert!(
            !chunk.data.contains(VICTIM_SECRET),
            "the symlink target's out-of-tree secret must NEVER reach a chunk"
        );
    }
}

#[test]
fn scan_unix_socket_in_tree_is_not_surfaced() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    let rows = scan_rows(dir.path().to_path_buf());
    assert_eq!(
        rows.len(),
        0,
        "a unix-domain socket is not a regular file and is dropped at the walk"
    );
}

#[test]
fn scan_symlink_to_dev_null_is_not_surfaced() {
    let dir = tempfile::tempdir().unwrap();
    symlink(Path::new("/dev/null"), dir.path().join("nulllink")).unwrap();
    let rows = scan_rows(dir.path().to_path_buf());
    assert_eq!(
        rows.len(),
        0,
        "a symlink (to a char device) is dropped at the walk with follow_symlinks(false)"
    );
}

#[test]
fn scan_full_special_file_matrix_yields_only_the_regular_file() {
    // regular file + FIFO + socket + out-of-tree symlink + dev-null symlink, all
    // in one tree. Only the regular file survives the walk.
    let victim_dir = tempfile::tempdir().unwrap();
    let victim = victim_dir.path().join("victim");
    std::fs::write(&victim, format!("{VICTIM_SECRET}\n")).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let body = format!("real = {IN_TREE_SECRET}\n");
    std::fs::write(dir.path().join("real.txt"), &body).unwrap();
    make_fifo(&dir.path().join("pipe"));
    let _listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    symlink(&victim, dir.path().join("alias.txt")).unwrap();
    symlink(Path::new("/dev/null"), dir.path().join("nulllink")).unwrap();

    let root = dir.path().to_path_buf();
    let rows = within_timeout(move || scan_rows(root));
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "no special file should emit an error here: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "exactly one chunk: the sole regular file; every special file is dropped"
    );
    assert_eq!(chunks[0].metadata.source_type.as_ref(), "filesystem");
    assert_eq!(&*chunks[0].data, body.as_str());
    assert!(
        !chunks[0].data.contains(VICTIM_SECRET),
        "the out-of-tree victim secret must not leak through the matrix scan"
    );
}

#[test]
fn scan_special_file_matrix_records_no_skip_gap() {
    // Special files dropped at the WALK (is_file()==false) are not counted as
    // skips, they never entered the scan set. Hold the exclusive counter scope
    // so a concurrent test cannot pollute the snapshot we assert.
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("real.txt"), format!("{IN_TREE_SECRET}\n")).unwrap();
    make_fifo(&dir.path().join("pipe"));
    let _listener = UnixListener::bind(dir.path().join("s.sock")).unwrap();
    symlink(Path::new("/dev/null"), dir.path().join("nulllink")).unwrap();

    let rows = scan_rows(dir.path().to_path_buf());
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(chunks.len(), 1, "only the regular file is scanned");
    assert!(errors.is_empty());
    assert_eq!(
        skip_counts(),
        SkipCounts::default(),
        "walk-dropped special files must bump NO skip counter, every category stays zero"
    );
}

#[test]
fn scan_archive_symlink_is_refused_with_a_counted_coverage_gap() {
    // A symlink whose name marks it as an EXPANDABLE container (`bait.zip`) is
    // the link-swap exfiltration class: following it would read AND structurally
    // expand an out-of-tree target. The archive-symlink audit refuses it with a
    // visible error and a counted Unreadable gap (Law 10: not a silent clean).
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let victim_dir = tempfile::tempdir().unwrap();
    let victim = victim_dir.path().join("secrets.txt");
    std::fs::write(&victim, format!("{VICTIM_SECRET}\n")).unwrap();

    let dir = tempfile::tempdir().unwrap();
    symlink(&victim, dir.path().join("bait.zip")).unwrap();

    let rows = scan_rows(dir.path().to_path_buf());
    let (chunks, errors) = split_chunk_results(&rows);
    for chunk in &chunks {
        assert!(
            !chunk.data.contains(VICTIM_SECRET),
            "an archive symlink must never expand its out-of-tree target"
        );
    }
    assert_eq!(
        errors.len(),
        1,
        "the refused archive symlink must surface exactly one SourceError row"
    );
    assert!(
        errors[0]
            .to_string()
            .contains("archive symlink expansion is blocked"),
        "the refusal must name the link-swap defense; got {}",
        errors[0]
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "a refused archive symlink is one counted Unreadable coverage gap"
    );
}

#[test]
fn scan_dangling_non_archive_symlink_is_a_silent_noop() {
    // A broken (dangling) NON-archive symlink is classified via read_link (which
    // succeeds on a dangling link), found non-expandable, and dropped at the walk
    //: no chunk, no error, no skip bump.
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();

    let dir = tempfile::tempdir().unwrap();
    symlink(
        Path::new("/nonexistent/target/path"),
        dir.path().join("alias.txt"),
    )
    .unwrap();

    let rows = scan_rows(dir.path().to_path_buf());
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(
        chunks.len(),
        0,
        "a dangling non-archive symlink yields no chunk"
    );
    assert!(errors.is_empty(), "and no error: {errors:?}");
    assert_eq!(
        skip_counts(),
        SkipCounts::default(),
        "a dangling non-archive symlink bumps no skip counter"
    );
}

#[test]
fn scan_fifo_beside_regular_file_still_scans_the_regular_file() {
    // Isolation + recall: a FIFO in the tree must neither hang the scan nor
    // suppress a regular sibling.
    let dir = tempfile::tempdir().unwrap();
    make_fifo(&dir.path().join("pipe"));
    let body = format!("after = {IN_TREE_SECRET}\n");
    std::fs::write(dir.path().join("after.txt"), &body).unwrap();

    let root = dir.path().to_path_buf();
    let rows = within_timeout(move || scan_rows(root));
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(errors.is_empty(), "no error rows expected: {errors:?}");
    assert_eq!(
        chunks.len(),
        1,
        "the FIFO drops out; the regular sibling remains"
    );
    assert_eq!(&*chunks[0].data, body.as_str());
    assert!(chunks[0].data.contains(IN_TREE_SECRET));
}
