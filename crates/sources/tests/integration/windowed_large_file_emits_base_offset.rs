//! Windowed scan of large files must populate base_offset metadata.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[test]
fn windowed_large_file_emits_base_offset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let payload = "OFFSET_MARKER=".to_string() + &"y".repeat(9000);
    std::fs::write(dir.path().join("wide.txt"), payload).expect("write");

    let source = TestApi.filesystem_with_window_config(dir.path().to_path_buf(), 4096, 512);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid windowed file must not emit SourceError rows, got {errors:?}"
    );
    assert!(
        chunks.len() >= 2,
        "window_size=4096 on 9k file must emit multiple windows; got {chunks:?}"
    );
    assert!(
        chunks.iter().any(|c| {
            c.metadata.source_type.as_ref() == "filesystem/windowed" && c.metadata.base_offset > 0
        }),
        "windowed chunks must carry non-zero base_offset; got {chunks:?}"
    );
}
