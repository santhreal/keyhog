//! 7z archives are source containers and must be unpacked.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

fn scan_file(name: &str, bytes: Vec<u8>) -> Vec<keyhog_core::Chunk> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), bytes).expect("write 7z fixture");
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "valid 7z fixture must not emit SourceError rows, got {errors:?}"
    );
    chunks.into_iter().cloned().collect()
}

#[test]
fn seven_zip_text_entry_is_unpacked_and_scanned_with_inner_path() {
    let chunks = scan_file(
        "bundle.7z",
        crate::support::archive::build_seven_zip(&[(
            "secrets.env",
            b"KEYHOG_7Z_MEMBER_SECRET_1234567890",
        )]),
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem/archive"
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("bundle.7z//secrets.env"))
                && chunk.data.contains("KEYHOG_7Z_MEMBER_SECRET_1234567890")
        }),
        "7z payload must unpack to an inner archive chunk; got {chunks:?}"
    );
}

#[test]
fn seven_zip_binary_strings_entry_is_scanned() {
    // The member must be GENUINELY binary so the canonical entry decoder
    // (`decode_text_file_owned_or_bytes`, shared with the plain filesystem read
    // path) classifies it as binary and falls back to printable-strings rather
    // than lossy text. A real binary carries a NUL run / high control density —
    // a couple of stray high bytes around clean ASCII decode as lossy *text*
    // (and would still surface the secret, just tagged `filesystem/archive`).
    // The 4+ NUL run here trips `has_repeated_nul_run`, the same binary signal a
    // loose `.bin` file would hit, keeping archive/binary classification in
    // parity with the filesystem path.
    let chunks = scan_file(
        "binary.7z",
        crate::support::archive::build_seven_zip(&[(
            "payload.bin",
            b"\x00\x00\x00\x00\xffKEYHOG_7Z_BINARY_STRING_SECRET_1234567890\xff\x00\x00\x00\x00",
        )]),
    );
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem/archive-binary"
                && chunk
                    .data
                    .contains("KEYHOG_7Z_BINARY_STRING_SECRET_1234567890")
        }),
        "7z binary member printable strings must be scanned; got {chunks:?}"
    );
}
