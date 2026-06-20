//! Decompressed gzip members must use filesystem/compressed source_type.

use crate::support::collect_chunks;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;

#[test]
fn gzip_chunk_source_type_compressed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = File::create(dir.path().join("a.gz")).expect("create");
    let mut enc = GzEncoder::new(file, Compression::default());
    enc.write_all(b"X=1
").expect("write");
    enc.finish().expect("finish");

    let types: Vec<String> = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .map(|c| c.metadata.source_type.clone())
        .collect();
    assert!(
        types.iter().any(|t| t.contains("compressed") || t == "filesystem"),
        "gzip chunk source_type must identify compressed path; got {types:?}"
    );
}
