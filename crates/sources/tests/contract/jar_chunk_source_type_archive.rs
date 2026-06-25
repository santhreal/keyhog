//! Jar text entries must use filesystem/archive source_type.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn jar_chunk_source_type_archive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = File::create(dir.path().join("app.jar")).expect("create");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("META-INF/env", opts).expect("start");
    zip.write_all(
        b"K=1
",
    )
    .expect("write");
    zip.finish().expect("finish");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid JAR fixture must not emit SourceError rows, got {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "single JAR text entry must emit exactly one chunk, got {chunks:?}"
    );
    let chunk = chunks[0];
    assert_eq!(chunk.metadata.source_type, "filesystem/archive");
    assert!(
        chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("app.jar//META-INF/env")),
        "JAR chunk path must identify archive and entry, got {:?}",
        chunk.metadata.path
    );
    assert!(chunk.data.contains("K=1"));
}
