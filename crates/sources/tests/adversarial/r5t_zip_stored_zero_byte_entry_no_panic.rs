//! R5-T archive adversarial: zip with zero-byte stored entry does not panic.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn r5t_zip_stored_zero_byte_entry_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    let zip_path = dir.path().join("empty-member.zip");
    let file = File::create(&zip_path).expect("create");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("empty.txt", opts).expect("start");
    zip.finish().expect("finish");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(
        chunks.len(),
        0,
        "zero-byte zip member must not yield scannable chunks"
    );
    assert!(
        errors.is_empty(),
        "valid zero-byte zip member should not emit SourceError rows: {errors:?}"
    );
}
