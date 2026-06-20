//! xz and bzip2 are compressed source containers, not binary skip extensions.

use crate::support::collect_chunks;
use bzip2::write::BzEncoder;
use bzip2::Compression;
use keyhog_sources::FilesystemSource;
use std::io::Write;
use xz2::write::XzEncoder;

fn scan_file(name: &str, bytes: Vec<u8>) -> Vec<keyhog_core::Chunk> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), bytes).expect("write compressed fixture");
    collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()))
        .into_iter()
        .collect()
}

fn encode_bzip2(plaintext: &[u8]) -> Vec<u8> {
    let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plaintext).expect("write bzip2 input");
    encoder.finish().expect("finish bzip2")
}

fn encode_xz(plaintext: &[u8]) -> Vec<u8> {
    let mut encoder = XzEncoder::new(Vec::new(), 6);
    encoder.write_all(plaintext).expect("write xz input");
    encoder.finish().expect("finish xz")
}

fn tar_with_file(name: &str, content: &[u8]) -> Vec<u8> {
    let mut tar_bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, content)
            .expect("append tar entry");
        builder.finish().expect("finish tar");
    }
    tar_bytes
}

#[test]
fn xz_plain_payload_is_decompressed_and_scanned() {
    let chunks = scan_file(
        "payload.xz",
        encode_xz(b"KEYHOG_XZ_COMPRESSED_SECRET_1234567890"),
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem/compressed"
                && chunk
                    .data
                    .contains("KEYHOG_XZ_COMPRESSED_SECRET_1234567890")
        }),
        "xz payload must emit filesystem/compressed chunk; got {chunks:?}"
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
            chunk.metadata.source_type == "filesystem/compressed"
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
            chunk.metadata.source_type == "filesystem/archive"
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
