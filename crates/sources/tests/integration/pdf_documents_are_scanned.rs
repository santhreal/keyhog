//! PDF files are structured containers, not text files. These tests prove the
//! dedicated PDF route extracts real PDF text streams while keeping provenance
//! distinct from the plain filesystem decoder.

use crate::support::split_chunk_results;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::io::Write;

fn scan_pdf(bytes: Vec<u8>) -> Vec<keyhog_core::Chunk> {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("document.pdf");
    std::fs::write(&path, bytes).expect("write pdf");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid PDF fixture must not emit SourceError rows, got {errors:?}"
    );
    chunks.into_iter().cloned().collect()
}

#[test]
fn pdf_literal_text_stream_is_scanned_as_pdf() {
    let bytes = crate::support::pdf::minimal_pdf(
        "",
        b"BT /F1 12 Tf 72 720 Td (KEYHOG_PDF_LITERAL_SECRET_1234567890) Tj ET",
    );

    let chunks = scan_pdf(bytes);
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem/pdf"
                && chunk.data.contains("KEYHOG_PDF_LITERAL_SECRET_1234567890")
        }),
        "PDF literal text stream must emit filesystem/pdf chunk; got {chunks:?}"
    );
    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.metadata.source_type != "filesystem"),
        "PDF bytes must not be decoded as plain filesystem text"
    );
}

#[test]
fn pdf_flate_text_stream_is_decompressed_and_scanned() {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(b"BT (KEYHOG_PDF_FLATE_SECRET_1234567890) Tj ET")
        .expect("write flate input");
    let compressed = encoder.finish().expect("finish flate");
    let bytes = crate::support::pdf::minimal_pdf(" /Filter /FlateDecode", &compressed);

    let chunks = scan_pdf(bytes);
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem/pdf"
                && chunk.data.contains("KEYHOG_PDF_FLATE_SECRET_1234567890")
        }),
        "FlateDecode PDF text stream must be decompressed and scanned; got {chunks:?}"
    );
}

#[test]
fn pdf_hex_text_string_is_decoded_and_scanned() {
    let bytes = crate::support::pdf::minimal_pdf(
        "",
        b"BT <4b4559484f475f5044465f4845585f5345435245545f31323334353637383930> Tj ET",
    );

    let chunks = scan_pdf(bytes);
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem/pdf"
                && chunk.data.contains("KEYHOG_PDF_HEX_SECRET_1234567890")
        }),
        "hex PDF text string must be decoded and scanned; got {chunks:?}"
    );
}
