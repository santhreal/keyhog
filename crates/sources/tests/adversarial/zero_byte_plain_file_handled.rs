//! Zero-byte text files must not panic and must not emit bogus chunks.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn zero_byte_plain_file_handled() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("empty.txt"), b"").expect("write empty");
    std::fs::write(dir.path().join("marker.txt"), "MARKER=visible\n").expect("write marker");

    let chunks: Vec<_> = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .collect();

    assert!(
        chunks.iter().any(|c| c.data.contains("MARKER=visible")),
        "readable neighbor must still be scanned"
    );
    assert!(
        !chunks.iter().any(|c| c
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.ends_with("empty.txt"))),
        "zero-byte file should be skipped, not surfaced as an empty chunk"
    );
}
