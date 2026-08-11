//! Read responsibility tests for filesystem read: mmap, windowed mmap,
//! and the compressed-input read path.

use keyhog_sources::testing::{
    for_each_file_windowed_mmap_for_test, ForEachWindowedMmapOutcome, TestApi,
};

/// Exact-size reads preserve shrink and growth semantics while retaining at
/// most the one-byte cap-crossing probe.
#[test]
fn stat_sized_read_preserves_content_and_growth_boundaries() {
    assert_eq!(
        TestApi
            .read_stat_sized_to_cap(b"exact", 5, 8)
            .expect("exact-sized read"),
        b"exact"
    );
    assert_eq!(
        TestApi
            .read_stat_sized_to_cap(b"short", 8, 8)
            .expect("stat-time shrink"),
        b"short"
    );
    assert_eq!(
        TestApi
            .read_stat_sized_to_cap(b"0123456789", 4, 8)
            .expect("stat-time growth"),
        b"012345678"
    );
    assert_eq!(
        TestApi
            .read_stat_sized_to_cap(b"growth", 0, 3)
            .expect("zero-to-nonzero growth"),
        b"grow"
    );
}

/// Regression: preserves the externally observable `read_file_windowed_mmap_roundtrip_matches_pure_helper` behavior after the inline suite split.
#[test]
fn read_file_windowed_mmap_roundtrip_matches_pure_helper() {
    // The mmap path is just slice_into_windows over the mmap'd
    // bytes. Write a small file, run both, assert identical.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.txt");
    let bytes: Vec<u8> = (0..u8::MAX).cycle().take(8192).collect();
    std::fs::write(&path, &bytes).unwrap();

    let pure = TestApi.slice_into_windows_with_offsets(&bytes, 1024, 32);
    let mapped = TestApi
        .read_file_windowed_mmap(&path, 1024, 32)
        .expect("mmap windows");
    assert_eq!(pure.len(), mapped.len());
    for (a, b) in pure.iter().zip(mapped.iter()) {
        assert_eq!(a.0, b.0);
        assert_eq!(a.1, b.1);
    }
}

/// Regression: preserves the externally observable `for_each_file_windowed_mmap_stops_on_consumer_backpressure` behavior after the inline suite split.
#[test]
fn for_each_file_windowed_mmap_stops_on_consumer_backpressure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.txt");
    let bytes: Vec<u8> = (0..u8::MAX).cycle().take(8192).collect();
    std::fs::write(&path, &bytes).unwrap();

    let mut seen = Vec::new();
    let mut errors = Vec::new();
    let mapped = for_each_file_windowed_mmap_for_test(&path, 1024, 32, |row| match row {
        Ok(window) => {
            seen.push((window.0, window.1.len()));
            false
        }
        Err(error) => {
            errors.push(error);
            false
        }
    });

    assert!(
        matches!(mapped, ForEachWindowedMmapOutcome::Consumed),
        "mmap path should own this file"
    );
    assert_eq!(seen.len(), 1, "consumer stop must halt window emission");
    assert!(
        errors.is_empty(),
        "normal consumer backpressure must not emit error rows: {errors:?}"
    );
    assert_eq!(seen[0].0, 0, "first streamed window starts at byte zero");
    assert!(seen[0].1 >= 1024, "lossy first window should be non-empty");
}

/// Regression: preserves the externally observable `read_file_for_compressed_input_returns_full_contents_via_mmap` behavior after the inline suite split.
#[test]
fn read_file_for_compressed_input_returns_full_contents_via_mmap() {
    // The mmap-or-bytes wrapper must round-trip an arbitrary
    // non-empty byte sequence - covers the common case where
    // compressed inputs are well within the size cap.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("blob.bin");
    // Use a payload with a mix of bytes so any truncation
    // manifests as a mismatch, not coincidentally-equal heads.
    let payload: Vec<u8> = (0..=255u8).cycle().take(8192).collect();
    std::fs::write(&path, &payload).unwrap();

    let fb = TestApi
        .read_file_for_compressed_input(&path, 1024 * 1024)
        .expect("read ok");
    assert_eq!(fb, payload);
    assert_eq!(fb.len(), payload.len());
}

/// Regression: preserves the externally observable `read_file_for_compressed_input_handles_empty_file` behavior after the inline suite split.
#[test]
fn read_file_for_compressed_input_handles_empty_file() {
    // mmap of zero-byte files is rejected on some platforms; the
    // helper must return Some(Owned(empty)) so callers don't
    // misinterpret None as a hard failure.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.bin");
    std::fs::write(&path, b"").unwrap();

    let fb = TestApi
        .read_file_for_compressed_input(&path, 1024)
        .expect("empty ok");
    assert!(fb.is_empty());
    assert_eq!(fb.len(), 0);
}

/// Regression: preserves the externally observable `read_file_for_compressed_input_refuses_oversize_input` behavior after the inline suite split.
#[test]
fn read_file_for_compressed_input_refuses_oversize_input() {
    // size_cap is the gate that keeps a 100 GiB compressed blob
    // out of memory entirely. The helper returns None and emits
    // a tracing warning - caller treats as "skip this file".
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.bin");
    std::fs::write(&path, vec![0u8; 4096]).unwrap();

    // cap below file size → refused.
    let fb = TestApi.read_file_for_compressed_input(&path, 1024);
    assert!(fb.is_none(), "input exceeding size_cap must return None");

    // cap at-or-above file size → accepted.
    let fb = TestApi.read_file_for_compressed_input(&path, 4096);
    assert!(fb.is_some(), "input at-or-below size_cap must succeed");

    // Source-level max_file_size=0 means unlimited. The compressed helper still
    // uses the hard TOCTOU sanity cap, but must not treat zero as "refuse every
    // non-empty compressed input".
    let fb = TestApi.read_file_for_compressed_input(&path, 0);
    assert!(
        fb.is_some(),
        "size_cap=0 must mean unlimited up to the hard sanity cap"
    );
}

/// Regression: preserves the externally observable `read_file_for_compressed_input_returns_none_for_missing_path` behavior after the inline suite split.
#[test]
fn read_file_for_compressed_input_returns_none_for_missing_path() {
    // Nonexistent path must NOT panic, and must return None so
    // the caller can move on cleanly. (Earlier implementations
    // did `std::fs::read(path)?` and bubbled the error; the new
    // wrapper folds that into None to match the Option-shaped
    // API the windowed helper uses.)
    let fb = TestApi.read_file_for_compressed_input(
        std::path::Path::new("/nonexistent/keyhog/test/path"),
        1024,
    );
    assert!(fb.is_none());
}

/// Regression: preserves the externally observable `read_file_windowed_mmap_handles_empty_file` behavior after the inline suite split.
#[test]
fn read_file_windowed_mmap_handles_empty_file() {
    // Zero-byte mmap is a corner case some platforms reject. The
    // helper must return either Some(empty vec) or None - never
    // panic. Either way the caller won't emit chunks.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.txt");
    std::fs::write(&path, b"").unwrap();
    // `None` is also acceptable: mmap of zero-length is refused
    // on some platforms. Either way the caller won't emit chunks.
    if let Some(v) = TestApi.read_file_windowed_mmap(&path, 1024, 32) {
        assert!(v.is_empty());
    }
}
