//! Valid single-member gzip must still surface inner secrets.

use crate::support::split_chunk_results;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;

#[test]
fn gzip_single_member_secret_survives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cfg.env.gz");
    let file = File::create(&path).expect("create");
    let mut enc = GzEncoder::new(file, Compression::default());
    enc.write_all(
        b"AWS_SECRET=super-secret-value
",
    )
    .expect("write");
    enc.finish().expect("finish");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid single-member gzip should not emit SourceError rows: {errors:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|chunk| chunk.data.contains("super-secret-value")),
        "gzip member must decompress; got {chunks:?}"
    );
    assert!(
        chunks.iter().any(|chunk| chunk
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.contains("cfg.env.gz"))),
        "gzip chunk path must identify the compressed source, got {chunks:?}"
    );
}
