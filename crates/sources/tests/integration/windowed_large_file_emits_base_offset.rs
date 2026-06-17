//! Windowed scan of large files must populate base_offset metadata.

use keyhog_core::Source;
use keyhog_sources::testing;

#[test]
fn windowed_large_file_emits_base_offset() {
    let dir = tempfile::tempdir().expect("tempdir");
    let payload = "OFFSET_MARKER=".to_string() + &"y".repeat(9000);
    std::fs::write(dir.path().join("wide.txt"), payload).expect("write");

    let source = testing::filesystem_with_window_config(dir.path().to_path_buf(), 4096, 512);
    let chunks: Vec<_> = source.chunks().flatten().collect();
    assert!(
        chunks.len() >= 2,
        "window_size=4096 on 9k file must emit multiple windows; got {chunks:?}"
    );
    assert!(
        chunks.iter().any(|c| {
            c.metadata.source_type == "filesystem/windowed" && c.metadata.base_offset > 0
        }),
        "windowed chunks must carry non-zero base_offset; got {chunks:?}"
    );
}
