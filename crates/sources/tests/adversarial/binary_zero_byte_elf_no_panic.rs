//! Zero-byte binary-looking file must not panic binary dispatch.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

#[test]
fn binary_zero_byte_elf_no_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("empty.bin"), []).expect("empty bin");
    std::fs::write(dir.path().join("note.txt"), "NOTE=ok\n").expect("note");

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    assert!(
        errors.is_empty(),
        "zero-byte binary skip should not emit SourceError rows: {errors:?}"
    );
    assert_eq!(
        chunks.len(),
        1,
        "zero-byte binary should emit no chunks while side file survives: {chunks:?}"
    );
    assert!(
        chunks[0].data.contains("NOTE=ok"),
        "side file must still scan when a zero-byte binary is present: {chunks:?}"
    );
    assert!(
        chunks[0]
            .metadata
            .path
            .as_deref()
            .is_some_and(|path| path.ends_with("note.txt")),
        "side chunk path must identify the scanned sibling, got {chunks:?}"
    );
}
