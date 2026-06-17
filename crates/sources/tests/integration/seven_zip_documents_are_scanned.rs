//! 7z archives are source containers and must be unpacked.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use std::io::Cursor;

fn build_seven_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ArchiveWriter::new(cursor).expect("create 7z writer");
    writer.set_encrypt_header(false);
    for (name, content) in entries {
        let entry = ArchiveEntry::new_file(name);
        writer
            .push_archive_entry(entry, Some(Cursor::new(*content)))
            .expect("push 7z entry");
    }
    writer.finish().expect("finish 7z").into_inner()
}

fn scan_file(name: &str, bytes: Vec<u8>) -> Vec<keyhog_core::Chunk> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), bytes).expect("write 7z fixture");
    FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .collect()
}

#[test]
fn seven_zip_text_entry_is_unpacked_and_scanned_with_inner_path() {
    let chunks = scan_file(
        "bundle.7z",
        build_seven_zip(&[("secrets.env", b"KEYHOG_7Z_MEMBER_SECRET_1234567890")]),
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
    let chunks = scan_file(
        "binary.7z",
        build_seven_zip(&[(
            "payload.bin",
            b"\x00\xffKEYHOG_7Z_BINARY_STRING_SECRET_1234567890\xfe\x00",
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
