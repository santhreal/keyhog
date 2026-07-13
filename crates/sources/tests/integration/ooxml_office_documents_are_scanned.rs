//! Recall: OOXML/ODF office documents (docx/xlsx/pptx/odt/ods/odp) are ZIP
//! containers whose text lives in member XML. A credential pasted into a
//! spreadsheet or doc is a real, common leak that keyhog previously dropped
//! SILENTLY at the walker (these extensions were in SKIP_EXTENSIONS, so the file
//! was never read and `SKIPPED_BINARY` was never even incremented, a Law-10
//! false-clean AND a recall hole). They are now routed through the existing
//! openpack/ZIP unpacker (`is_openpack_archive_ext`), so the member XML is
//! scanned like any other archived file.
//!
//! These tests build minimal-but-real OOXML/ODF ZIPs with a secret in the
//! member XML and assert the secret's bytes surface as an extracted chunk
//! (Law 6: assert the real credential, not `!is_empty`).

use crate::support::split_chunk_results;
use keyhog_core::{Chunk, Source};
use keyhog_sources::FilesystemSource;
use std::fs::File;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// A fake-but-checksum-shaped AWS access key id (distinctive bytes to assert on).
const SECRET: &str = "AKIAQYLPMN5HFIQR7XYA";

fn write_zip(path: &std::path::Path, members: &[(&str, String)]) {
    use std::io::Write;
    let file = File::create(path).expect("create office doc");
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, body) in members {
        zip.start_file(*name, opts).expect("start member");
        zip.write_all(body.as_bytes()).expect("write member");
    }
    zip.finish().expect("finish zip");
}

fn extracted_chunks(dir: &std::path::Path) -> Vec<Chunk> {
    let source = FilesystemSource::new(dir.to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid office-document fixture must not emit SourceError rows, got {errors:?}"
    );
    chunks.into_iter().cloned().collect()
}

#[test]
fn xlsx_shared_strings_secret_is_scanned() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Minimal OOXML skeleton: the spreadsheet's shared-string table holds the
    // cell text, which is where a pasted credential lands.
    write_zip(
        &dir.path().join("budget.xlsx"),
        &[
            (
                "[Content_Types].xml",
                "<?xml version=\"1.0\"?><Types/>".to_string(),
            ),
            (
                "xl/sharedStrings.xml",
                format!("<?xml version=\"1.0\"?><sst><si><t>aws_key {SECRET}</t></si></sst>"),
            ),
        ],
    );

    let chunks = extracted_chunks(dir.path());
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type.as_ref() == "filesystem/archive"
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("budget.xlsx//xl/sharedStrings.xml"))
                && chunk.data.contains(SECRET)
        }),
        "the xlsx sharedStrings secret must be extracted and scannable; got {chunks:?}"
    );
}

#[test]
fn docx_document_xml_secret_is_scanned() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_zip(
        &dir.path().join("notes.docx"),
        &[
            (
                "[Content_Types].xml",
                "<?xml version=\"1.0\"?><Types/>".to_string(),
            ),
            (
                "word/document.xml",
                format!(
                    "<?xml version=\"1.0\"?><w:document><w:body><w:p><w:r><w:t>token {SECRET}</w:t></w:r></w:p></w:body></w:document>"
                ),
            ),
        ],
    );

    let chunks = extracted_chunks(dir.path());
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type.as_ref() == "filesystem/archive"
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("notes.docx//word/document.xml"))
                && chunk.data.contains(SECRET)
        }),
        "the docx document.xml secret must be extracted and scannable; got {chunks:?}"
    );
}

#[test]
fn ods_content_xml_secret_is_scanned() {
    let dir = tempfile::tempdir().expect("tempdir");
    // OpenDocument spreadsheet: text lives in content.xml.
    write_zip(
        &dir.path().join("sheet.ods"),
        &[
            ("mimetype", "application/vnd.oasis.opendocument.spreadsheet".to_string()),
            (
                "content.xml",
                format!("<?xml version=\"1.0\"?><office:document-content><text>{SECRET}</text></office:document-content>"),
            ),
        ],
    );

    let chunks = extracted_chunks(dir.path());
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type.as_ref() == "filesystem/archive"
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("sheet.ods//content.xml"))
                && chunk.data.contains(SECRET)
        }),
        "the ods content.xml secret must be extracted and scannable; got {chunks:?}"
    );
}
