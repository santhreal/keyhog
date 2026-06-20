//! Jar entries whose declared uncompressed size exceeds max_file_size are skipped.

use super::support::count_chunks;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn jar_oversized_entry_metadata_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let jar_path = dir.path().join("fat.jar");
    let file = File::create(&jar_path).expect("create jar");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("huge.bin", opts).expect("start");
    zip.write_all(format!("TOKEN=should-not-appear\n{}", "x".repeat(4096)).as_bytes())
        .expect("write");
    zip.finish().expect("finish");

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(512);
    let count = count_chunks(&source);
    assert_eq!(count, 0, "over-cap jar entries must be skipped");
}
