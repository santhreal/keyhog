//! PDF extraction failures are coverage gaps, not clean scans.
//!
//! Own test binary: the skip counters are process-global atomics. Keeping these
//! assertions out of `tests/all_tests.rs` lets the fixture reset the counters
//! without racing unrelated source tests in the same process.

#[path = "support/pdf.rs"]
mod pdf_support;

use flate2::write::ZlibEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{skip_counts, FilesystemSource};
use std::io::Write;

fn write_pdf(bytes: &[u8]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("bad.pdf"), bytes).expect("write pdf");
    dir
}

fn drain_pdf(bytes: &[u8]) {
    let dir = write_pdf(bytes);
    let _chunks = FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .collect::<Vec<_>>();
}

#[test]
fn pdf_extraction_failures_bump_unreadable_gaps() {
    TestApi.reset_skip_counters();
    drain_pdf(b"%PDF-1.7\ntrailer\n<< /Encrypt 2 0 R >>\n%%EOF\n");
    drain_pdf(
        b"%PDF-1.7\n1 0 obj\n<< /Length 17 /Filter /FlateDecode >>\nstream\nnot-a-flate-stream\nendstream\nendobj\n%%EOF\n",
    );
    assert_eq!(
        skip_counts().unreadable,
        2,
        "encrypted PDFs and corrupt FlateDecode streams must both be surfaced as unreadable coverage gaps"
    );
}

#[test]
fn pdf_decoded_stream_truncation_surfaces_source_error() {
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
    let chunks: Vec<_> = rows.iter().filter_map(|row| row.as_ref().ok()).collect();
    let errors: Vec<_> = rows.iter().filter_map(|row| row.as_ref().err()).collect();

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
