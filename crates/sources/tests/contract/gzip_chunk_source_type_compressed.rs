//! Decompressed gzip members must use filesystem/compressed source_type.

use crate::support::split_chunk_results;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;

#[test]
fn gzip_chunk_source_type_compressed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = File::create(dir.path().join("a.gz")).expect("create");
    let mut enc = GzEncoder::new(file, Compression::default());
    enc.write_all(
        b"X=1
",
    )
    .expect("write");
    enc.finish().expect("finish");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid gzip fixture must not emit SourceError rows, got {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "single gzip member must emit exactly one chunk, got {chunks:?}"
    );
    let chunk = chunks[0];
    assert_eq!(chunk.metadata.source_type.as_ref(), "filesystem/compressed");
    assert!(
        chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("a.gz")),
        "gzip chunk path must identify compressed input, got {:?}",
        chunk.metadata.path
    );
    assert!(chunk.data.contains("X=1"));
}
