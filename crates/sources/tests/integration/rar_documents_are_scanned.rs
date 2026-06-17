//! RAR archives are source containers and must be unpacked.

use base64::Engine;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

const VERSION_RAR_BASE64: &str =
    "UmFyIRoHAM+QcwAADQAAAAAAAAAPDHQggCcAFQAAAAsAAAADRfN9xqSKB0cdMwcApIEAAFZFUlNJT04MAI/sikXMI8hICINi/l/dXFOI8HLEPXsAQAcA";

fn version_rar_bytes() -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(VERSION_RAR_BASE64)
        .expect("embedded RAR fixture must decode")
}

fn scan_file(name: &str, bytes: Vec<u8>) -> Vec<keyhog_core::Chunk> {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(name), bytes).expect("write RAR fixture");
    FilesystemSource::new(dir.path().to_path_buf())
        .chunks()
        .flatten()
        .collect()
}

#[test]
fn rar_text_entry_is_unpacked_and_scanned_with_inner_path() {
    let chunks = scan_file("bundle.rar", version_rar_bytes());
    assert!(
        chunks.iter().any(|chunk| {
            chunk.metadata.source_type == "filesystem/archive"
                && chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(|path| path.ends_with("bundle.rar//VERSION"))
                && chunk.data.contains("unrar-0.4.0")
        }),
        "RAR payload must unpack to an inner archive chunk; got {chunks:?}"
    );
}
