//! Jar entries whose declared uncompressed size exceeds max_file_size are skipped.

use keyhog_sources::FilesystemSource;
use keyhog_core::Source;
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
    // Write tiny payload but we cannot fake central-directory size easily via zip crate;
    // instead use max_file_size=0 to force skip of any positive uncompressed entry.
    zip.write_all(b"TOKEN=should-not-appear
").expect("write");
    zip.finish().expect("finish");

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(0);
    let count = source.chunks().flatten().count();
    assert_eq!(count, 0, "max_file_size=0 must skip jar entries");
}
