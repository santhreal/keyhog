//! xz/bzip2 decode failures are source coverage gaps, not clean scans.

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

fn drain(name: &str, bytes: &[u8]) -> Vec<String> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), bytes).expect("write fixture");
    FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .filter_map(Result::err)
        .map(|error| error.to_string())
        .collect()
}

#[test]
fn corrupt_xz_and_bzip2_streams_bump_unreadable_gaps() {
    let _guard = TestApi.skip_counter_guard();
    TestApi.reset_skip_counters();
    let mut errors = drain("bad.xz", b"\xfd7zXZ\x00not-a-valid-xz-stream");
    errors.extend(drain("bad.bz2", b"BZhnot-a-valid-bzip2-stream"));
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
