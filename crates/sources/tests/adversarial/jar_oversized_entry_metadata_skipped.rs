//! Jar entries whose declared uncompressed size exceeds max_file_size are skipped visibly.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{reset_skipped_over_max_size, skip_counts, FilesystemSource};
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn jar_oversized_entry_metadata_skipped() {
    let _guard = TestApi.skip_counter_guard();
    reset_skipped_over_max_size();
    let dir = tempfile::tempdir().expect("tempdir");
    let jar_path = dir.path().join("fat.jar");
    let file = File::create(&jar_path).expect("create jar");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("huge.bin", opts).expect("start");
    zip.write_all(format!("TOKEN=should-not-appear\n{}", "x".repeat(4096)).as_bytes())
        .expect("write");
    zip.finish().expect("finish");

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(512);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert_eq!(chunks.len(), 0, "over-cap jar entries must be skipped");
    assert_eq!(
        errors.len(),
        1,
        "over-cap jar entries must emit one visible SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("fat.jar//huge.bin")
            && error.contains("uncompressed size")
            && error.contains("exceeds per-file cap")
            && error.contains("entry was not scanned"),
        "over-cap jar error must name the skipped entry and cap reason, got {error}"
    );
    assert_eq!(
        skip_counts().over_max_size,
        1,
        "over-cap jar entry must be counted as an over-max-size coverage gap"
    );
}
