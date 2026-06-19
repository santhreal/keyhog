//! KH-GAP-158: Homoglyph coverage beyond single AKIA test.

use std::path::PathBuf;

#[test]
fn r5_homoglyph_beyond_single_aws() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/homoglyph");
    let count = std::fs::read_dir(&dir)
        .expect("homoglyph")
        .map(|e| e.unwrap_or_else(|err| panic!("read_dir({}) entry failed: {err}", dir.display())))
        .filter(|e| e.file_name().to_string_lossy().starts_with("homoglyph_"))
        .count();
    assert!(
        count >= 6,
        "KH-GAP-158: homoglyph adversarial floor, got {count}"
    );
}
