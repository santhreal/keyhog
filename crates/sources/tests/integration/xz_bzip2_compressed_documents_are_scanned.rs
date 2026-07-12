//! xz and bzip2 are compressed source containers, not binary skip extensions.

use crate::support::archive::{encode_xz, tar_with_file};
use crate::support::split_chunk_results;
use bzip2::write::BzEncoder;
use bzip2::Compression;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::io::Write;

fn scan_file(name: &str, bytes: Vec<u8>) -> Vec<keyhog_core::Chunk> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), bytes).expect("write compressed fixture");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid compressed fixture must not emit SourceError rows, got {errors:?}"
    );
    chunks.into_iter().cloned().collect()
}

fn encode_bzip2(plaintext: &[u8]) -> Vec<u8> {
    let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plaintext).expect("write bzip2 input");
    encoder.finish().expect("finish bzip2")
}

#[test]
fn xz_plain_payload_is_decompressed_and_scanned() {
    let chunks = scan_file(
        "payload.xz",
        encode_xz(b"KEYHOG_XZ_COMPRESSED_SECRET_1234567890"),
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type.as_ref() == "filesystem/compressed"
                && chunk
                    .data
                    .contains("KEYHOG_XZ_COMPRESSED_SECRET_1234567890")
        }),
        "xz payload must emit filesystem/compressed chunk; got {chunks:?}"
    );
}

#[test]
fn uppercase_xz_extension_is_decompressed_and_scanned() {
    let chunks = scan_file(
        "payload.XZ",
        encode_xz(b"KEYHOG_UPPER_XZ_COMPRESSED_SECRET_1234567890"),
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type.as_ref() == "filesystem/compressed"
                && chunk
                    .data
                    .contains("KEYHOG_UPPER_XZ_COMPRESSED_SECRET_1234567890")
        }),
        "uppercase .XZ payload must route to compressed extraction without lowercase allocation; got {chunks:?}"
    );
}

#[test]
fn bzip2_plain_payload_is_decompressed_and_scanned() {
    let chunks = scan_file(
        "payload.bz2",
        encode_bzip2(b"KEYHOG_BZIP2_COMPRESSED_SECRET_1234567890"),
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type.as_ref() == "filesystem/compressed"
                && chunk
                    .data
                    .contains("KEYHOG_BZIP2_COMPRESSED_SECRET_1234567890")
        }),
        "bzip2 payload must emit filesystem/compressed chunk; got {chunks:?}"
    );
}

#[test]
fn tar_xz_payload_is_untarred_and_scanned_with_inner_path() {
    let tar_bytes = tar_with_file("secrets.env", b"KEYHOG_TAR_XZ_MEMBER_SECRET_1234567890");
    let chunks = scan_file("archive.tar.xz", encode_xz(&tar_bytes));
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type.as_ref() == "filesystem/archive"
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("archive.tar.xz//secrets.env"))
                && chunk
                    .data
                    .contains("KEYHOG_TAR_XZ_MEMBER_SECRET_1234567890")
        }),
        "tar.xz payload must untar to an inner archive chunk; got {chunks:?}"
    );
}
