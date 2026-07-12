//! Size-cap contract for the public `read_file_safe_bytes` (companion to
//! `filesystem_read_missing_path_err`, which covers the missing-path arm). The
//! documented contract (safe_read.rs): a file EXCEEDING the effective byte budget
//! returns `ErrorKind::InvalidData` rather than being read into unbounded memory
//! — the OOM / TOCTOU-grown-file guard (Law 7). `max_bytes == 0` is the "no caller
//! budget" sentinel: only the walker's hard 2 GiB ceiling applies, so a small
//! file still reads. Prior coverage (the inline `#[cfg(all(test, unix))]` mod)
//! exercised regular/FIFO/symlink/missing but NOT the size cap. The
//! `read_exact_stat_sized_with_growth_probe` one-byte sentinel makes the boundary
//! exact: file size `> cap` errors, `== cap` succeeds.

use keyhog_sources::read_file_safe_bytes;
use std::io::ErrorKind;
use std::path::PathBuf;

fn write_file(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("payload.bin");
    std::fs::write(&path, bytes).expect("write payload");
    (dir, path)
}

/// A file LARGER than the caller's budget is refused with `InvalidData`, never
/// read into memory — the core OOM guard.
#[test]
fn file_exceeding_max_bytes_is_rejected_with_invalid_data() {
    let (_dir, path) = write_file(&[b'x'; 100]);
    let err = read_file_safe_bytes(&path, 50)
        .expect_err("a 100-byte file under a 50-byte budget must be refused, not read");
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidData,
        "an over-budget file must map to InvalidData; got {err}"
    );
}

/// BOUNDARY: a file EXACTLY at the budget reads fully (the guard is `size > cap`,
/// not `>=`) and returns the exact bytes — a legitimate at-limit file is not lost.
#[test]
fn file_exactly_at_max_bytes_reads_all_bytes() {
    let (_dir, path) = write_file(&[b'y'; 100]);
    let bytes = read_file_safe_bytes(&path, 100).expect("a file exactly at the budget must read");
    assert_eq!(
        bytes,
        vec![b'y'; 100],
        "the exact file bytes must be returned"
    );
}

/// A file UNDER the budget reads normally (the cap never truncates legitimate
/// sub-budget input).
#[test]
fn file_under_max_bytes_reads_all_bytes() {
    let (_dir, path) = write_file(&[b'z'; 100]);
    let bytes = read_file_safe_bytes(&path, 1000).expect("an under-budget file must read");
    assert_eq!(bytes, vec![b'z'; 100]);
}

/// `max_bytes == 0` is the "no caller budget" sentinel — only the hard 2 GiB
/// ceiling applies, so a small file still reads. `0` must NOT mean "reject
/// everything" / "read nothing".
#[test]
fn max_bytes_zero_sentinel_reads_a_small_file() {
    let (_dir, path) = write_file(&[b'w'; 100]);
    let bytes = read_file_safe_bytes(&path, 0)
        .expect("max_bytes=0 sentinel must still read a small file, not reject it");
    assert_eq!(bytes, vec![b'w'; 100]);
}
