//! KH-GAP-147: Concat adversarial floor.

use std::path::PathBuf;

#[test]
fn r5_concat_adversarial_floor_7() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/concat");
    let count = std::fs::read_dir(&dir)
        .expect("concat")
        .map(|e| e.unwrap_or_else(|err| panic!("read_dir({}) entry failed: {err}", dir.display())))
        .filter(|e| e.file_name().to_string_lossy().starts_with("concat_"))
        .count();
    assert!(count >= 7, "KH-GAP-147: floor 7, got {count}");
}
