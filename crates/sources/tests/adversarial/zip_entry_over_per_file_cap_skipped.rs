//! Single archive entries declaring uncompressed size above max_file_size are skipped visibly.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{reset_skipped_over_max_size, skip_counts, FilesystemSource};
use std::fs::File;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[test]
fn zip_entry_over_per_file_cap_skipped() {
    let _guard = TestApi.skip_counter_guard();
    reset_skipped_over_max_size();
    let dir = tempfile::tempdir().expect("tempdir");

    let control = dir.path().join("control.zip");
    let file = File::create(&control).expect("create control");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("tiny-ok.txt", opts).expect("start ok");
    zip.write_all(b"SAFE=1\n").expect("write ok");
    zip.finish().expect("finish control");

    let bomb = dir.path().join("bigentry.zip");
    let file = File::create(&bomb).expect("create bomb");
    let mut zip = ZipWriter::new(file);
    let compressed_opts =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("huge.bin", compressed_opts)
        .expect("start huge");
    zip.write_all(&vec![b'H'; 2048]).expect("write huge");
    zip.finish().expect("finish bomb");

    let source = FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(512);
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<String> = chunks.into_iter().map(|c| c.data.to_string()).collect();

    assert!(
        bodies.iter().any(|b| b.contains("SAFE=1")),
        "control archive with only small entries must still unpack"
    );
    assert!(
        !bodies.iter().any(|b| b.contains('H') && b.len() > 100),
        "oversized archive entry must be skipped entirely; got {bodies:?}"
    );
    assert_eq!(
        errors.len(),
        1,
        "oversized archive entry must emit one visible SourceError"
    );
    let error = errors[0].to_string();
    assert!(
        error.contains("bigentry.zip//huge.bin")
            && error.contains("uncompressed size")
            && error.contains("exceeds per-file cap")
            && error.contains("entry was not scanned"),
        "over-cap entry error must name the skipped entry and cap reason, got {error}"
    );
    let counts = skip_counts();
    assert_eq!(
        counts.over_max_size, 1,
        "oversized archive entries must be counted as over-max-size coverage gaps"
    );
    assert_eq!(
        counts.unreadable, 0,
        "oversized archive entries are not unreadable/corrupt inputs"
    );
}
