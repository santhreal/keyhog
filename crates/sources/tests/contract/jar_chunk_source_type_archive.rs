//! Jar text entries must use filesystem/archive source_type.

use crate::support::collect_chunks;
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

    let types: Vec<String> = collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .map(|c| c.metadata.source_type.clone())
        .collect();
    assert!(
        types.iter().any(|t| t == "filesystem/archive"),
        "expected filesystem/archive; got {types:?}"
    );
}
