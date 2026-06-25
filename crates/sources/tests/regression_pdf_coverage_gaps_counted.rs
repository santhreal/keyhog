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
fn non_pdf_extension_text_fallback_keeps_plain_files_scannable() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    TestApi.reset_skip_counters();

    let rows = scan_pdf(b"KEYHOG_NOT_ACTUALLY_PDF_TEXT_SECRET_1234567890\n");
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        errors.is_empty(),
        "non-PDF text with a .pdf extension should not emit coverage errors: {errors:?}"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem"
                && chunk
                    .data
                    .contains("KEYHOG_NOT_ACTUALLY_PDF_TEXT_SECRET_1234567890")
        }),
        "non-PDF text with a .pdf extension must still scan as filesystem text; chunks={chunks:?}"
    );
    assert_eq!(
        skip_counts().total(),
        0,
        "plain text with a .pdf extension is fully scanned, not a coverage gap"
    );
}

#[test]
fn non_pdf_extension_binary_strings_fallback_preserves_printable_runs() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    TestApi.reset_skip_counters();

    let rows = scan_pdf(b"\0\0\0KEYHOG_NOT_PDF_BINARY_STRING_SECRET_1234567890\0\0\0");
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        errors.is_empty(),
        "non-PDF binary-string fallback should not emit source errors: {errors:?}"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem:binary-strings"
                && chunk
                    .data
                    .contains("KEYHOG_NOT_PDF_BINARY_STRING_SECRET_1234567890")
        }),
        "non-PDF binary .pdf files with printable strings must keep the printable run; chunks={chunks:?}"
    );
    assert_eq!(
        skip_counts().total(),
        0,
        "binary-string recovery scans the admitted printable bytes and should not count a skip"
    );
}

#[test]
fn non_pdf_extension_binary_without_strings_counts_binary_skip() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    TestApi.reset_skip_counters();

    let rows = scan_pdf(b"\0\x01\x02\x03\x04\x05\x06\x07");
    let (chunks, errors) = split_chunk_results(&rows);

    assert!(
        chunks.is_empty() && errors.is_empty(),
        "pure binary .pdf impostors without printable strings should yield no chunks or errors; rows={rows:?}"
    );
    assert_eq!(
        skip_counts().binary,
        1,
        "pure binary .pdf impostors must count one binary skip"
    );
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
fn pdf_missing_endstream_and_unsupported_filter_count_unreadable_gaps() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    TestApi.reset_skip_counters();

    let missing_endstream =
        scan_pdf(b"%PDF-1.7\n1 0 obj\n<< /Length 16 >>\nstream\nBT (secret) Tj\nendobj\n%%EOF\n");
    let unsupported_filter = scan_pdf(&pdf_support::minimal_pdf(
        " /Filter /LZWDecode",
        b"BT (KEYHOG_PDF_UNSUPPORTED_FILTER_SECRET_1234567890) Tj ET",
    ));
    let (_missing_chunks, missing_errors) = split_chunk_results(&missing_endstream);
    let (_unsupported_chunks, unsupported_errors) = split_chunk_results(&unsupported_filter);

    assert_eq!(
        missing_errors.len(),
        1,
        "missing endstream must surface one source error row"
    );
    assert!(
        missing_errors[0]
            .to_string()
            .contains("stream without endstream marker"),
        "missing-endstream error should name the unscanned gap, got {}",
        missing_errors[0]
    );
    assert_eq!(
        unsupported_errors.len(),
        1,
        "unsupported PDF filters must surface one source error row"
    );
    assert!(
        unsupported_errors[0]
            .to_string()
            .contains("unsupported stream filter"),
        "unsupported-filter error should name the unscanned gap, got {}",
        unsupported_errors[0]
    );
    assert_eq!(
        skip_counts().unreadable,
        2,
        "missing endstream and unsupported filters must both count unreadable coverage gaps"
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

#[test]
fn pdf_partial_flate_recovery_surfaces_archive_truncated_gap() {
    let _guard = COUNTER_LOCK.lock().unwrap();
    TestApi.reset_skip_counters();

    let mut decoded = b"BT (KEYHOG_PDF_RECOVERED_SECRET_1234567890) Tj ET\n".to_vec();
    decoded.extend(vec![b'A'; 60 * 1024]);
    let len = u16::try_from(decoded.len()).expect("fixture fits in one stored block");
    let nlen = !len;
    let mut compressed = vec![0x78, 0x01, 0x00];
    compressed.extend_from_slice(&len.to_le_bytes());
    compressed.extend_from_slice(&nlen.to_le_bytes());
    compressed.extend_from_slice(&decoded);
    compressed.push(0x06);

    let pdf = pdf_support::minimal_pdf(" /Filter /FlateDecode", &compressed);
    let rows = scan_pdf(&pdf);
    let (chunks, errors) = split_chunk_results(&rows);

    assert_eq!(
        errors.len(),
        1,
        "partial PDF FlateDecode recovery must surface one source error row"
    );
    let err = errors[0].to_string();
    assert!(
        err.contains("failed after recovering decoded text")
            && err.contains("only the recovered prefix was scanned")
            && err.contains("remaining PDF stream bytes were not scanned"),
        "error should describe partial PDF recovery coverage, got {err}"
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem/pdf"
                && chunk
                    .data
                    .contains("KEYHOG_PDF_RECOVERED_SECRET_1234567890")
        }),
        "recovered PDF text must still emit the admitted chunk; chunks={chunks:?}"
    );
    assert_eq!(
        skip_counts().archive_truncated,
        1,
        "partial PDF FlateDecode recovery must bump ARCHIVE_TRUNCATED exactly once"
    );
}
