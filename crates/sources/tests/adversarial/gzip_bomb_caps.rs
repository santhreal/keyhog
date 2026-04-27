//! Verify the gzip-bomb cap path doesn't panic on malformed compressed
//! input. The audit release-2026-04-26 hardening added a 4× per-file
//! decompression budget on top of the existing per-file cap, but a
//! malformed `.gz` (truncated header, bad CRC, invalid block) should
//! also be tolerated cleanly — empty Vec returned, no panic.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs;

#[test]
fn malformed_gzip_does_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    // Bytes that look gzip-y (correct magic, wrong everything else).
    let bogus = [0x1f, 0x8b, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
    fs::write(dir.path().join("malformed.gz"), bogus).unwrap();
    fs::write(
        dir.path().join("good.py"),
        "API_KEY = 'AKIAIOSFODNN7EXAMPLE'",
    )
    .unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    // The malformed entry should be silently skipped (or yield an Err
    // without panicking); good.py must still come through.
    let mut found_good = false;
    for c in source.chunks().flatten() {
        if c.metadata
            .path
            .as_deref()
            .is_some_and(|p| p.ends_with("good.py"))
        {
            found_good = true;
        }
    }
    assert!(
        found_good,
        "good.py must still be returned alongside the malformed gz"
    );
}

#[test]
fn empty_gzip_is_handled() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("empty.gz"), []).unwrap();
    fs::write(
        dir.path().join("good.py"),
        "TOKEN = 'xoxb-real-secret-here'",
    )
    .unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    // Empty .gz must not crash the iterator.
    let _: Vec<_> = source.chunks().collect();
}

#[test]
fn random_bytes_with_gz_extension_dont_panic() {
    let dir = tempfile::tempdir().unwrap();
    // 256 random-ish bytes labelled .gz — the format dispatcher will
    // route them to the gzip path; ziftsieve should bail cleanly.
    let mut buf = Vec::with_capacity(256);
    for i in 0..256u32 {
        // Knuth's multiplicative hash; wrapping_mul to avoid the overflow
        // panic in debug builds — we just want a deterministic byte stream.
        buf.push((i.wrapping_mul(2654435761) >> 24) as u8);
    }
    fs::write(dir.path().join("rand.gz"), &buf).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    // Just iterating must not panic; result count is unimportant.
    let _ = source.chunks().collect::<Vec<_>>();
}
