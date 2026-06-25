//! xz/bzip2 decode failures are source coverage gaps, not clean scans.

mod support;

use keyhog_core::{Chunk, Source};
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use support::split_chunk_results;

fn drain(name: &str, bytes: &[u8]) -> (Vec<Chunk>, Vec<String>) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), bytes).expect("write fixture");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    (
        chunks.into_iter().cloned().collect(),
        errors.into_iter().map(|error| error.to_string()).collect(),
    )
}

#[test]
fn corrupt_xz_and_bzip2_streams_bump_unreadable_gaps() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let (chunks_xz, mut errors) = drain("bad.xz", b"\xfd7zXZ\x00not-a-valid-xz-stream");
    let (chunks_bz2, errors_bz2) = drain("bad.bz2", b"BZhnot-a-valid-bzip2-stream");
    errors.extend(errors_bz2);
    assert!(
        chunks_xz.is_empty() && chunks_bz2.is_empty(),
        "corrupt xz/bzip2 fixtures must not emit clean chunks; got xz={chunks_xz:?} bz2={chunks_bz2:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        2,
        "corrupt xz and bzip2 streams must both be surfaced as unreadable coverage gaps"
    );
    assert_eq!(
        errors.len(),
        2,
        "corrupt xz and bzip2 streams must emit visible source errors"
    );
    for error in errors {
        assert!(
            error.contains("failed to scan compressed file")
                && error.contains("failed to decompress file")
                && error.contains("was not scanned"),
            "compressed error should name the unscanned coverage gap, got {error}"
        );
    }
}
