//! 7z archives that cannot be read must increment skip counters.

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn corrupt_seven_zip_counts_as_unreadable() {
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("broken.7z"), b"not a seven zip archive")
        .expect("write corrupt 7z");

    let chunks: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();

    assert!(
        chunks.is_empty(),
        "corrupt 7z should emit no chunks: {chunks:?}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "corrupt 7z coverage gap must be counted as unreadable"
    );
}
