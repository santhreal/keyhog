//! KH-GAP-159: Concat adversarial files beyond engine_cases.

use std::path::PathBuf;

#[test]
fn r5_concat_beyond_engine_cases() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/concat");
    let count = std::fs::read_dir(&dir)
        .expect("concat")
        .map(|e| e.unwrap_or_else(|err| panic!("read_dir({}) entry failed: {err}", dir.display())))
        .filter(|e| e.file_name().to_string_lossy().starts_with("concat_"))
        .count();
    assert!(
        count >= 6,
        "KH-GAP-159: concat adversarial floor, got {count}"
    );
}
