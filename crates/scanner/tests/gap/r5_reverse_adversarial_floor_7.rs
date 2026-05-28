//! KH-GAP-148: Reverse adversarial floor.

use std::path::PathBuf;

#[test]
fn r5_reverse_adversarial_floor_7() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/reverse");
    let count = std::fs::read_dir(&dir)
        .expect("reverse")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("reverse_"))
        .count();
    assert!(count >= 7, "KH-GAP-148: floor 7, got {count}");
}
