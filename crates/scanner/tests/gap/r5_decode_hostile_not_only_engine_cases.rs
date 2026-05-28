//! KH-GAP-156: Decode hostile coverage outside engine_cases only.

use std::path::PathBuf;

#[test]
fn r5_decode_hostile_not_only_engine_cases() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/a3_decode");
    let hostile = std::fs::read_dir(&dir)
        .expect("a3_decode")
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("decode_hostile_"))
        .count();
    assert!(hostile >= 10, "KH-GAP-156: need standalone decode_hostile files, got {hostile}");
}
