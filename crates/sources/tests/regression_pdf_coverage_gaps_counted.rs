//! PDF extraction failures are coverage gaps, not clean scans.
//!
//! Own test binary: the skip counters are process-global atomics. Keeping these
//! assertions out of `tests/all_tests.rs` lets the fixture reset the counters
//! without racing unrelated source tests in the same process.

#[path = "support/pdf.rs"]
mod pdf_support;

mod support;

use flate2::write::ZlibEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use std::io::Write;
use std::sync::Mutex;
use support::split_chunk_results;

static COUNTER_LOCK: Mutex<()> = Mutex::new(());

fn write_pdf(bytes: &[u8]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("bad.pdf"), bytes).expect("write pdf");
    dir
}

fn scan_pdf(bytes: &[u8]) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
    let dir = write_pdf(bytes);
    FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect::<Vec<_>>()
}

#[test]
fn pdf_extraction_failures_emit_source_errors_and_count_unreadable_gaps() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    TestApi.reset_skip_counters();
    let encrypted = scan_pdf(b"%PDF-1.7\ntrailer\n<< /Encrypt 2 0 R >>\n%%EOF\n");
    let corrupt = scan_pdf(
        b"%PDF-1.7\n1 0 obj\n<< /Length 17 /Filter /FlateDecode >>\nstream\nnot-a-flate-stream\nendstream\nendobj\n%%EOF\n",
    );
    let (_encrypted_chunks, encrypted_errors) = split_chunk_results(&encrypted);
    let (_corrupt_chunks, corrupt_errors) = split_chunk_results(&corrupt);
    assert_eq!(
        encrypted_errors.len(),
        1,
        "encrypted PDF must surface one source error row"
    );
    assert!(
        encrypted_errors[0].to_string().contains("encrypted PDF")
            && encrypted_errors[0]
                .to_string()
                .contains("affected PDF bytes were not scanned"),
        "encrypted PDF error should describe unscanned coverage, got {}",
        encrypted_errors[0]
    );
    assert_eq!(
        corrupt_errors.len(),
        1,
        "corrupt PDF stream must surface one source error row"
    );
    assert!(
        corrupt_errors[0]
            .to_string()
            .contains("stream decode failed before producing text")
            && corrupt_errors[0]
                .to_string()
                .contains("affected PDF bytes were not scanned"),
        "corrupt PDF error should describe unscanned coverage, got {}",
        corrupt_errors[0]
    );
    assert_eq!(
        skip_counts().unreadable,
        2,
        "encrypted PDFs and corrupt FlateDecode streams must both be surfaced as unreadable coverage gaps"
    );
}

#[test]
fn pdf_decoded_stream_truncation_surfaces_source_error() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    TestApi.reset_skip_counters();
    const MAX_FILE_SIZE: u64 = 2048;
    let mut decoded = b"BT (KEYHOG_PDF_TRUNCATED_PREFIX_SECRET_1234567890) Tj ET\n".to_vec();
    decoded.extend(vec![b'A'; 16 * 1024]);

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&decoded).expect("write flate input");
    let compressed = encoder.finish().expect("finish flate");
    let pdf = pdf_support::minimal_pdf(" /Filter /FlateDecode", &compressed);
    assert!(
        pdf.len() <= MAX_FILE_SIZE as usize,
        "fixture must stay under the outer file cap so PDF extraction reaches the decoded-stream budget; pdf bytes={}",
        pdf.len()
    );

    let dir = write_pdf(&pdf);
    let rows: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
        .with_max_file_size(MAX_FILE_SIZE)
        .chunks()
        .collect();
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(
        errors.len(),
        1,
        "PDF decoded-stream truncation must surface one source error row"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("PDF extraction")
            && err.contains("remaining decoded PDF stream bytes were not scanned"),
        "error should describe partial PDF coverage, got {err}"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem/pdf"
                && chunk
                    .data
                    .contains("KEYHOG_PDF_TRUNCATED_PREFIX_SECRET_1234567890")
        }),
        "truncated PDF prefix must still emit the admitted text chunk; chunks={chunks:?}"
    );
    assert_eq!(
        skip_counts().archive_truncated,
        1,
        "PDF decoded-stream truncation must bump ARCHIVE_TRUNCATED exactly once"
    );
}
