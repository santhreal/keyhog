//! RAR archives that cannot be read must increment skip counters.

use keyhog_core::Source;
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn corrupt_rar_counts_as_unreadable() {
    keyhog_sources::testing::reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("broken.rar"), b"not a rar archive").expect("write corrupt RAR");

    let chunks: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();

    assert!(
        chunks.is_empty(),
        "corrupt RAR should emit no chunks: {chunks:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "corrupt RAR coverage gap must be counted as unreadable"
    );
}
