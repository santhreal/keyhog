//! KH-GAP-157: Chunk boundary coverage beyond AKIA-only.

use std::path::PathBuf;

#[test]
fn r5_chunk_boundary_not_only_aws() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/chunk_boundary");
    let count = std::fs::read_dir(&dir)
        .expect("chunk_boundary")
        .map(|e| e.unwrap_or_else(|err| panic!("read_dir({}) entry failed: {err}", dir.display())))
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with("chunk_boundary_") && name.ends_with("_split_reassembled.rs")
        })
        .count();
    assert!(
        count >= 8,
        "KH-GAP-157: chunk boundary must cover multiple detectors, got {count}"
    );
}
