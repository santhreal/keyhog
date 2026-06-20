//! 7z archives that cannot be read must emit a source error and increment skip
//! counters.

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};

#[test]
fn corrupt_seven_zip_counts_as_unreadable() {
    TestApi.reset_skip_counters();
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("broken.7z"), b"not a seven zip archive")
        .expect("write corrupt 7z");

    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect();

    assert_eq!(
        rows.len(),
        1,
        "corrupt 7z should emit one visible source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("corrupt 7z must be an error row");
    assert!(
        err.to_string().contains("cannot open archive")
            && err.to_string().contains("archive was not scanned"),
        "error should name the unscanned 7z archive, got {err}"
    );
    assert_eq!(
        skip_counts().unreadable,
        1,
        "corrupt 7z coverage gap must be counted as unreadable"
    );
}
