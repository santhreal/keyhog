//! KH-GAP-145: Chunk-boundary adversarial floor.

use std::path::PathBuf;

#[test]
fn r5_chunk_boundary_adversarial_floor_12() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/chunk_boundary");
    let count = std::fs::read_dir(&dir)
        .expect("chunk_boundary")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("chunk_boundary_"))
        .count();
    assert!(count >= 12, "KH-GAP-145: floor 12, got {count}");
}
