//! #129 symlink-race / TOCTOU lock: the BINARY content read must honor the same
//! `open_file_safe` boundary (O_NOFOLLOW + O_NONBLOCK + post-open fd fstat) every
//! other content read uses.
//!
//! Before the fix `read_binary_capped` opened with a raw `std::fs::File::open`,
//! which:
//!   * BLOCKS FOREVER on a writer-less FIFO target (no `O_NONBLOCK`), a single
//!     named pipe handed to the binary source would hang the scan;
//!   * FOLLOWS a symlinked binary path (no `O_NOFOLLOW`), so a
//!     `evil.bin -> ~/.aws/credentials` link redirects the read to an off-target
//!     file, the link-swap class the filesystem path defends against (M17);
//!   * STREAMS a character device (`/dev/zero`) until the read cap instead of
//!     refusing it.
//!
//! Routing it through `open_file_safe` closes all three. This suite drives the
//! PUBLIC `BinarySource` path (`TestApi.binary_strings_only(path).chunks()`) and
//! pins: the FIFO returns instead of hanging, every symlink / special file is
//! refused with a counted coverage gap, a symlink target's secret never leaks,
//! and a REAL regular binary still scans (recall preserved).
//!
//! The binary unreadable/skip counters are PROCESS-GLOBAL atomics, so every test
//! here acquires `COUNTER_LOCK` and resets the counters at entry (`guarded()`):
//! a refusal in one test would otherwise pollute another's exact-count assertion.

#![cfg(all(unix, feature = "binary"))]

mod support;

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{binary_unreadable, reset_binary_counters, skip_counts};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use support::split_chunk_results;

/// Serialises the process-global binary-counter mutations in this test binary.
static COUNTER_LOCK: Mutex<()> = Mutex::new(());

/// A printable sentinel (>= 8 bytes) for recall/leak checks. Not a credential
/// shape, so it never needs a `keyhog:ignore` and never trips the self-scan; the
/// strings extractor surfaces it purely on length.
const SENTINEL: &str = "KEYHOG_BINARY_SCAN_SENTINEL_9f3a01";
const SENTINEL_B: &str = "KEYHOG_SECOND_SENTINEL_b7c2d4e6";

/// Acquire the serialising lock and reset both counters to a clean slate. Every
/// test calls this first, so concurrent refusals never pollute a count assertion.
/// Poison is recovered (`into_inner`) so a single failing assert isolates to that
/// test instead of cascading `PoisonError` through the rest of the binary.
fn guarded() -> MutexGuard<'static, ()> {
    let guard = COUNTER_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    reset_binary_counters();
    TestApi.reset_skip_counters();
    guard
}

/// Run `f` on a worker thread and REQUIRE it to finish within `secs`. A blocking
/// `open(O_RDONLY)` of a writer-less FIFO never returns, so this is the guard
/// proving the binary read returns instead of hanging.
fn within_timeout<T: Send + 'static>(secs: u64, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(secs)).expect(
        "binary read hung past the timeout, a writer-less FIFO open without O_NONBLOCK blocks \
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

/// Collect the binary source's emitted rows for `path` (strings-only, so the
/// read always reaches `read_binary_capped`).
fn scan_rows(path: PathBuf) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
    TestApi.binary_strings_only(path).chunks().collect()
}

fn assert_refused(rows: &[Result<keyhog_core::Chunk, keyhog_core::SourceError>], what: &str) {
    assert_eq!(
        rows.len(),
        1,
        "{what} must surface exactly one source error row"
    );
    let err = rows[0]
        .as_ref()
        .err()
        .unwrap_or_else(|| panic!("{what} must be refused with an error row"));
    assert!(
        err.to_string().contains("cannot read file")
            && err.to_string().contains("not scanned for secrets"),
        "{what} error should name the unreadable coverage gap; got {err}"
    );
}

// ── no-hang: the O_NONBLOCK half of the fix ─────────────────────────────────

#[test]
fn binary_fifo_target_returns_instead_of_hanging() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe.bin");
    make_fifo(&fifo);
    // A raw blocking open would never return here; within_timeout fails the test
    // if the read hangs.
    let fifo_for_worker = fifo.clone();
    let rows = within_timeout(10, move || scan_rows(fifo_for_worker));
    assert_refused(&rows, "a FIFO binary target");
    drop(dir);
}

#[test]
fn binary_symlink_to_fifo_returns_instead_of_hanging() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe");
    make_fifo(&fifo);
    let link = dir.path().join("link.bin");
    symlink(&fifo, &link).unwrap();
    let link_for_worker = link.clone();
    // O_NOFOLLOW refuses the symlink before O_NONBLOCK is even tested, but either
    // way the read must return rather than block on the pipe behind the link.
    let rows = within_timeout(10, move || scan_rows(link_for_worker));
    assert_refused(&rows, "a symlink-to-FIFO binary target");
    drop(dir);
}

// ── symlink refusal: the O_NOFOLLOW half of the fix ─────────────────────────

#[test]
fn binary_symlink_to_regular_file_is_refused() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real.bin");
    std::fs::write(&target, format!("prefix_{SENTINEL}_suffix").as_bytes()).unwrap();
    let link = dir.path().join("link.bin");
    symlink(&target, &link).unwrap();
    assert_refused(&scan_rows(link), "a symlinked regular binary");
}

#[test]
fn binary_symlink_target_secret_does_not_leak() {
    let _g = guarded();
    // The "victim" lives outside any walked tree, reachable only via the link.
    let dir = tempfile::tempdir().unwrap();
    let victim = dir.path().join("victim_credentials");
    std::fs::write(&victim, format!("SECRET_BODY_{SENTINEL}_MORE").as_bytes()).unwrap();
    let bait = dir.path().join("payload.bin");
    symlink(&victim, &bait).unwrap();

    let rows = scan_rows(bait);
    for row in rows.iter().flatten() {
        assert!(
            !row.data.contains(SENTINEL),
            "the symlink target's secret must NEVER appear in a scanned chunk; \
             O_NOFOLLOW must refuse the link before its target is read"
        );
    }
}

#[test]
fn binary_dangling_symlink_is_refused() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("dangling.bin");
    symlink(dir.path().join("nonexistent_target"), &link).unwrap();
    assert_refused(&scan_rows(link), "a dangling symlink binary target");
}

#[test]
fn binary_symlink_to_directory_is_refused() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let subdir = dir.path().join("adir");
    std::fs::create_dir(&subdir).unwrap();
    let link = dir.path().join("dirlink.bin");
    symlink(&subdir, &link).unwrap();
    assert_refused(&scan_rows(link), "a symlink-to-directory binary target");
}

#[test]
fn binary_symlink_chain_to_regular_is_refused() {
    let _g = guarded();
    // link2 -> link1 -> real: O_NOFOLLOW refuses the FIRST hop, so the chain is
    // never resolved to the real file.
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.bin");
    std::fs::write(&real, format!("body_{SENTINEL}").as_bytes()).unwrap();
    let link1 = dir.path().join("link1");
    symlink(&real, &link1).unwrap();
    let link2 = dir.path().join("link2.bin");
    symlink(&link1, &link2).unwrap();
    assert_refused(&scan_rows(link2), "a symlink chain binary target");
}

// ── special-file refusal ────────────────────────────────────────────────────

#[test]
fn binary_unix_socket_is_refused() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    assert_refused(&scan_rows(sock), "a unix-socket binary target");
}

#[test]
fn binary_directory_path_is_refused() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let subdir = dir.path().join("adir");
    std::fs::create_dir(&subdir).unwrap();
    assert_refused(&scan_rows(subdir), "a directory binary target");
}

// ── coverage accounting (Law 10): every refusal is a counted gap, not clean ──

#[test]
fn binary_fifo_refusal_counts_one_unreadable() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe.bin");
    make_fifo(&fifo);
    let fifo_for_worker = fifo.clone();
    let rows = within_timeout(10, move || scan_rows(fifo_for_worker));
    assert_refused(&rows, "a FIFO binary target");
    assert_eq!(
        binary_unreadable(),
        1,
        "a refused FIFO must count one unreadable drop"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "and flow through the shared skip snapshot"
    );
    drop(dir);
}

#[test]
fn binary_symlink_refusal_counts_one_unreadable() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real.bin");
    std::fs::write(&target, b"some printable body content here").unwrap();
    let link = dir.path().join("link.bin");
    symlink(&target, &link).unwrap();
    assert_refused(&scan_rows(link), "a symlinked binary");
    assert_eq!(
        binary_unreadable(),
        1,
        "a refused symlink must count one unreadable drop"
    );
    assert_eq!(skip_counts().unreadable, 1);
}

#[test]
fn binary_socket_refusal_counts_one_unreadable() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    assert_refused(&scan_rows(sock), "a unix-socket binary target");
    assert_eq!(binary_unreadable(), 1);
    assert_eq!(skip_counts().unreadable, 1);
}

#[test]
fn binary_dev_zero_is_refused_as_unreadable_not_streamed() {
    // The key NEW behavior: /dev/zero (a char device) is refused as a non-regular
    // file (unreadable), NOT read as an endless zero stream. On the old raw-open
    // path it read cap bytes of zeros and counted a binary GAP, never unreadable
    // so this `binary_unreadable() == 1` assertion is the crisp lock on the fix.
    let _g = guarded();
    let zero = PathBuf::from("/dev/zero");
    assert!(
        zero.exists(),
        "/dev/zero is missing on this host, cannot validate device refusal"
    );
    let rows = within_timeout(10, move || scan_rows(zero));
    assert_refused(&rows, "the /dev/zero character device");
    assert_eq!(
        binary_unreadable(),
        1,
        "/dev/zero must be refused as a non-regular file (unreadable), not streamed"
    );
}

#[test]
fn binary_dev_null_is_refused_as_unreadable() {
    // /dev/null is also a char device. The old raw open succeeded and read 0
    // bytes (EOF) → a binary gap, never unreadable; the safe open refuses it as a
    // non-regular file. Distinct device class from /dev/zero (which would stream).
    let _g = guarded();
    let null = PathBuf::from("/dev/null");
    assert!(null.exists(), "/dev/null is missing on this host");
    let rows = within_timeout(10, move || scan_rows(null));
    assert_refused(&rows, "the /dev/null character device");
    assert_eq!(
        binary_unreadable(),
        1,
        "/dev/null must be refused as a non-regular file, not read as an empty regular file"
    );
}

#[test]
fn binary_symlink_to_unix_socket_is_refused() {
    // link.bin -> a unix socket: O_NOFOLLOW refuses the link before the socket is
    // ever opened (a socket open would itself fail, but the link must be the gate).
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("real.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    let link = dir.path().join("link.bin");
    symlink(&sock, &link).unwrap();
    assert_refused(&scan_rows(link), "a symlink-to-socket binary target");
    assert_eq!(
        binary_unreadable(),
        1,
        "a symlink-to-socket refusal counts one unreadable drop"
    );
}

// ── error-message quality (UX): the refusal names the path ──────────────────

#[test]
fn binary_refusal_error_names_the_path() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("named.sock");
    let _listener = UnixListener::bind(&sock).unwrap();
    let rows = scan_rows(sock.clone());
    let err = rows[0].as_ref().err().expect("socket refused").to_string();
    assert!(
        err.contains(&sock.display().to_string()),
        "the refusal error must name the offending path so the operator can act; got {err}"
    );
}

// ── recall preserved: a REAL regular binary still scans ─────────────────────

#[test]
fn real_regular_binary_secret_surfaces() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("app.bin");
    let mut bytes = vec![0u8; 16];
    bytes.extend_from_slice(format!("junk_{SENTINEL}_tail").as_bytes());
    bytes.extend_from_slice(&[0u8; 16]);
    std::fs::write(&bin, &bytes).unwrap();

    let rows = scan_rows(bin);
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a real regular binary must not error; got {errors:?}"
    );
    assert!(
        chunks.iter().any(|c| c.data.contains(SENTINEL)),
        "the embedded printable string must still be extracted after the safe-open change"
    );
    assert_eq!(
        binary_unreadable(),
        0,
        "a readable binary must NOT be counted unreadable"
    );
}

#[test]
fn real_regular_binary_two_secrets_both_surface() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("two.bin");
    let mut bytes = Vec::new();
    bytes.extend_from_slice(format!("aaa_{SENTINEL}_bbb").as_bytes());
    bytes.extend_from_slice(&[0u8; 8]);
    bytes.extend_from_slice(format!("ccc_{SENTINEL_B}_ddd").as_bytes());
    std::fs::write(&bin, &bytes).unwrap();

    let rows = scan_rows(bin);
    let (chunks, _errors) = split_chunk_results(&rows);
    let all: String = chunks.iter().map(|c| c.data.to_string()).collect();
    assert!(all.contains(SENTINEL), "first secret must surface");
    assert!(all.contains(SENTINEL_B), "second secret must surface");
}

#[test]
fn empty_regular_binary_is_not_counted_unreadable() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("empty.bin");
    std::fs::write(&bin, b"").unwrap();
    // An empty regular file opens fine (it is a regular file); it just yields no
    // printable strings. That is a binary gap, NOT an unreadable refusal.
    let _rows = scan_rows(bin);
    assert_eq!(
        binary_unreadable(),
        0,
        "an empty REGULAR binary must not be misclassified as unreadable by the safe open"
    );
}

#[test]
fn regular_binary_after_fifo_refusal_still_scans() {
    let _g = guarded();
    // Isolation: refusing a FIFO must not poison a subsequent regular-file scan
    // (no leaked lock / fd / state from the O_NONBLOCK refusal path).
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe.bin");
    make_fifo(&fifo);
    let fifo_for_worker = fifo.clone();
    let _ = within_timeout(10, move || scan_rows(fifo_for_worker));

    let bin = dir.path().join("after.bin");
    std::fs::write(&bin, format!("post_{SENTINEL}_run").as_bytes()).unwrap();
    let rows = scan_rows(bin);
    let (chunks, _errors) = split_chunk_results(&rows);
    assert!(
        chunks.iter().any(|c| c.data.contains(SENTINEL)),
        "a regular binary scanned after a FIFO refusal must still surface its secret"
    );
    drop(dir);
}

#[test]
fn real_regular_binary_does_not_count_skip() {
    let _g = guarded();
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("clean.bin");
    std::fs::write(&bin, format!("body_{SENTINEL}_end").as_bytes()).unwrap();
    let _rows = scan_rows(bin);
    assert_eq!(
        skip_counts().unreadable,
        0,
        "a clean regular binary records no unreadable gap"
    );
}
