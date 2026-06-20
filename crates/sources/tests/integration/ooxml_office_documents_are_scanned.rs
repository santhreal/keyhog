//! Recall: OOXML/ODF office documents (docx/xlsx/pptx/odt/ods/odp) are ZIP
//! containers whose text lives in member XML. A credential pasted into a
//! spreadsheet or doc is a real, common leak that keyhog previously dropped
//! SILENTLY at the walker (these extensions were in SKIP_EXTENSIONS, so the file
//! was never read and `SKIPPED_BINARY` was never even incremented — a Law-10
//! false-clean AND a recall hole). They are now routed through the existing
//! openpack/ZIP unpacker (`is_openpack_archive_ext`), so the member XML is
//! scanned like any other archived file.
//!
//! These tests build minimal-but-real OOXML/ODF ZIPs with a secret in the
//! member XML and assert the secret's bytes surface as an extracted chunk
//! (Law 6: assert the real credential, not `!is_empty`).

use crate::support::collect_chunks;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// A fake-but-checksum-shaped AWS access key id — distinctive bytes to assert on.
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

fn extracted_bodies(dir: &std::path::Path) -> Vec<String> {
    collect_chunks(&FilesystemSource::new(dir.to_path_buf()))
        .into_iter()
        .map(|c| c.data.to_string())
        .collect()
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

    let bodies = extracted_bodies(dir.path());
    assert!(
        bodies.iter().any(|b| b.contains(SECRET)),
        "the xlsx sharedStrings secret must be extracted and scannable; got {bodies:?}"
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

    let bodies = extracted_bodies(dir.path());
    assert!(
        bodies.iter().any(|b| b.contains(SECRET)),
        "the docx document.xml secret must be extracted and scannable; got {bodies:?}"
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

    let bodies = extracted_bodies(dir.path());
    assert!(
        bodies.iter().any(|b| b.contains(SECRET)),
        "the ods content.xml secret must be extracted and scannable; got {bodies:?}"
    );
}
