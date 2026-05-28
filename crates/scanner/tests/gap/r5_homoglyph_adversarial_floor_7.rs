//! KH-GAP-146: Homoglyph adversarial floor.

use std::path::PathBuf;

#[test]
fn r5_homoglyph_adversarial_floor_7() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/homoglyph");
    let count = std::fs::read_dir(&dir)
        .expect("homoglyph")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("homoglyph_"))
        .count();
    assert!(count >= 7, "KH-GAP-146: floor 7, got {count}");
}
