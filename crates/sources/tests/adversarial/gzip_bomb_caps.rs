//! Verify the gzip-bomb cap path fails loud on malformed compressed
//! input. The audit release-2026-04-26 hardening added a 4× per-file
//! decompression budget on top of the existing per-file cap, but a
//! malformed `.gz` (truncated header, bad CRC, invalid block) should
//! also preserve neighboring-file coverage.

use super::support::assert_compressed_error;
use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use std::fs;

#[test]
fn malformed_gzip_fails_loud_and_scan_continues() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
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
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let found_good = chunks.iter().any(|c| {
        c.metadata
            .path
            .as_deref()
            .is_some_and(|p| p.ends_with("good.py"))
    });
    assert!(
        found_good,
        "good.py must still be returned alongside the malformed gz"
    );
    assert_eq!(
        errors.len(),
        1,
        "malformed gzip must emit one visible source error"
    );
    assert_compressed_error(errors[0]);
    assert_eq!(
        skip_counts().unreadable,
        1,
        "malformed gzip must count one unreadable coverage gap"
    );
}

#[test]
fn empty_gzip_fails_loud_without_panic() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("empty.gz"), []).unwrap();
    fs::write(
        dir.path().join("good.py"),
        "TOKEN = 'xoxb-real-secret-here'",
    )
    .unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        chunks.iter().any(|c| c
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.ends_with("good.py"))),
        "neighboring good.py must still be scanned"
    );
    assert_eq!(
        errors.len(),
        1,
        "empty gzip must emit one visible source error"
    );
    assert_compressed_error(errors[0]);
    assert_eq!(
        skip_counts().unreadable,
        1,
        "empty gzip must count one unreadable coverage gap"
    );
}

#[test]
fn random_bytes_with_gz_extension_fail_loud() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().unwrap();
    // 256 random-ish bytes labelled .gz - the format dispatcher will
    // route them to the gzip path; ziftsieve should bail cleanly.
    let mut buf = Vec::with_capacity(256);
    for i in 0..256u32 {
        // Knuth's multiplicative hash; wrapping_mul to avoid the overflow
        // panic in debug builds - we just want a deterministic byte stream.
        buf.push((i.wrapping_mul(2654435761) >> 24) as u8);
    }
    fs::write(dir.path().join("rand.gz"), &buf).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (_chunks, errors) = split_chunk_results(&rows);
    assert_eq!(
        errors.len(),
        1,
        "random .gz must emit one visible source error"
    );
    assert_compressed_error(errors[0]);
    assert_eq!(
        skip_counts().unreadable,
        1,
        "random .gz bytes must count one unreadable coverage gap"
    );
}
