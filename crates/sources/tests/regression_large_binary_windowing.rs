//! Regression coverage for large binary files crossing the filesystem window threshold.
//!
//! Large files normally use lossy UTF-8 windows. Native binaries must instead use
//! the whole-file decoder so their printable strings retain binary provenance.

#![cfg(feature = "binary")]

use keyhog_core::Source;
use keyhog_sources::testing::{TestApi};

/// An ELF larger than the configured scan window must not become ordinary text,
/// because compiled bytes then produce named and entropy false positives.
#[test]
fn large_elf_uses_binary_strings_instead_of_text_windows() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let path = dir.path().join("libfixture.so.3");
    let marker = "PRINTABLE_BINARY_MARKER_1234567890";
    let mut bytes = vec![0u8; 256];
    bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
    bytes[96..96 + marker.len()].copy_from_slice(marker.as_bytes());
    std::fs::write(&path, bytes).expect("write ELF fixture");

    let chunks = TestApi
        .filesystem_with_window_config(dir.path().to_path_buf(), 128, 32)
        .chunks()
        .collect::<Result<Vec<_>, _>>()
        .expect("scan ELF fixture");

    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.metadata.source_type.as_ref() != "filesystem/windowed"),
        "large ELF bytes must never be emitted as lossy text windows: {chunks:?}"
    );
    let binary = chunks
        .iter()
        .find(|chunk| chunk.metadata.source_type.as_ref() == "filesystem:binary-strings")
        .expect("large ELF must emit a binary-strings chunk");
    assert!(
        binary.data.contains(marker),
        "printable binary content must remain scannable: {binary:?}"
    );
    assert_eq!(binary.metadata.base_offset, 0);
    assert_eq!(binary.metadata.size_bytes, Some(256));
}
