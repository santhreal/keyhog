//! xz/bzip2 decode failures are source coverage gaps, not clean scans.

use keyhog_core::Source;
use keyhog_sources::{skip_counts, testing::reset_skip_counters, FilesystemSource};

fn drain(name: &str, bytes: &[u8]) {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), bytes).expect("write fixture");
    let _chunks = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect::<Vec<_>>();
}

#[test]
fn corrupt_xz_and_bzip2_streams_bump_unreadable_gaps() {
    reset_skip_counters();
    drain("bad.xz", b"\xfd7zXZ\x00not-a-valid-xz-stream");
    drain("bad.bz2", b"BZhnot-a-valid-bzip2-stream");
    assert_eq!(
        skip_counts().unreadable,
        2,
        "corrupt xz and bzip2 streams must both be surfaced as unreadable coverage gaps"
    );
}
