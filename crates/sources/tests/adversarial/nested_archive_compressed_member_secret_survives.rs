//! A compressed member (`.gz`) nested inside another archive must have its TRUE
//! decompressed bytes scanned, not its raw compressed bytes routed to the
//! printable-strings path.
//!
//! REGRESSION (Law 10 silent false-clean, found by dogfood): the tar and zip
//! extractors only recursed into members of their OWN format (tar->tar,
//! zip->zip). A `.gz` member fell through to the leaf decode: the gzip bytes are
//! not valid text, so they were scanned as printable strings. When the gzip
//! happened to carry a few printable bytes the scan "succeeded" and reported
//! "No secrets detected" with EXIT 0 and NO coverage gap -- a SILENT false
//! clean for a secret hidden in the compressed payload. `archive.tar//x.txt.gz`
//! and `bundle.zip//layer.tar//x.txt.gz` both vanished this way. Both extractors
//! now decompress a recognized compressed member in memory and scan its real
//! bytes (untarring if it is a tar), bounded by the existing depth and
//! tar/zip-bomb budgets.

use crate::support::split_chunk_results;
use flate2::write::GzEncoder;
use flate2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::io::Write;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// A real AWS access-key id shape, so the bytes that must survive are a genuine
/// secret a scanner is supposed to find -- not an arbitrary marker.
const SECRET: &str = "AWS_ACCESS_KEY_ID=AKIAQYLPMN5HFIQR7XYA";

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(bytes).expect("gzip write");
    enc.finish().expect("gzip finish")
}

fn tar_with(member_name: &str, member_bytes: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path(member_name).expect("tar path");
    header.set_size(member_bytes.len() as u64);
    header.set_cksum();
    builder.append(&header, member_bytes).expect("tar append");
    builder.into_inner().expect("tar finish")
}

fn zip_with(member_name: &str, member_bytes: &[u8]) -> Vec<u8> {
    let mut zip = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    // Stored: the member bytes are themselves already-compressed archives; the
    // outer zip must not re-compress and hide them from the magic sniff.
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file(member_name, opts).expect("zip start");
    zip.write_all(member_bytes).expect("zip write");
    zip.finish().expect("zip finish").into_inner()
}

fn scan_bytes(file_name: &str, bytes: &[u8]) -> Vec<keyhog_core::Chunk> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(file_name), bytes).expect("write fixture");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, _errors) = split_chunk_results(&rows);
    chunks.into_iter().cloned().collect()
}

#[test]
fn tar_with_gz_member_secret_survives() {
    // `archive.tar` -> `secret.txt.gz` -> the secret. Previously SILENT clean.
    let gz = gzip(format!("{SECRET}\n").as_bytes());
    let tar = tar_with("secret.txt.gz", &gz);
    let chunks = scan_bytes("archive.tar", &tar);
    assert!(
        chunks.iter().any(|c| c.data.contains(SECRET)),
        "secret inside archive.tar//secret.txt.gz must be decompressed and scanned, \
         not silently dropped; got {chunks:?}"
    );
    assert!(
        chunks.iter().any(|c| c
            .metadata
            .path
            .as_deref()
            .is_some_and(|p| p.contains("archive.tar//secret.txt.gz"))),
        "the nested compressed-member path must be surfaced; got {chunks:?}"
    );
}

#[test]
fn zip_with_compressed_tar_gz_member_secret_survives() {
    // `bundle.zip` -> `inner.tar.gz` (gzip of a tar) -> `secret.env` -> secret.
    // Previously the zip extractor leaf-scanned the gz member (recall loss).
    let inner_tar = tar_with("secret.env", format!("{SECRET}\n").as_bytes());
    let inner_tar_gz = gzip(&inner_tar);
    let zip = zip_with("inner.tar.gz", &inner_tar_gz);
    let chunks = scan_bytes("bundle.zip", &zip);
    assert!(
        chunks.iter().any(|c| c.data.contains(SECRET)),
        "secret inside bundle.zip//inner.tar.gz//secret.env must be found; got {chunks:?}"
    );
}

#[test]
fn zip_with_tar_with_gz_member_secret_survives() {
    // `bundle.zip` -> `layer.tar` -> `secret.txt.gz` -> secret. Three layers,
    // crossing zip -> tar -> gz. Previously SILENT clean (the zip leaf-scanned
    // the .tar member).
    let gz = gzip(format!("{SECRET}\n").as_bytes());
    let tar = tar_with("secret.txt.gz", &gz);
    let zip = zip_with("layer.tar", &tar);
    let chunks = scan_bytes("bundle.zip", &zip);
    assert!(
        chunks.iter().any(|c| c.data.contains(SECRET)),
        "secret inside bundle.zip//layer.tar//secret.txt.gz must be found; got {chunks:?}"
    );
}

#[test]
fn tar_with_benign_gz_member_stays_clean_without_error() {
    // Negative twin: a benign gz member must decompress, scan clean, and emit NO
    // SourceError coverage-gap row -- the recursion must not turn a clean member
    // into a spurious skip.
    let benign = b"this is an ordinary log line with no credentials at all\n";
    let gz = gzip(benign);
    let tar = tar_with("notes.txt.gz", &gz);
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("archive.tar"), &tar).expect("write");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "a benign compressed member must not emit a coverage-gap error: {errors:?}"
    );
    assert!(
        chunks
            .iter()
            .any(|c| c.data.contains("ordinary log line")),
        "the benign member's decompressed text must be scanned; got {chunks:?}"
    );
    assert!(
        !chunks.iter().any(|c| c.data.contains("AKIA")),
        "no AWS key shape should appear in benign content; got {chunks:?}"
    );
}
