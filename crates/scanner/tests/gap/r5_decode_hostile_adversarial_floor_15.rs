//! KH-GAP-144: Decode hostile adversarial floor.

use std::path::PathBuf;

#[test]
fn r5_decode_hostile_adversarial_floor_15() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/a3_decode");
    let count = std::fs::read_dir(&dir)
        .expect("a3_decode")
        .map(|e| e.unwrap_or_else(|err| panic!("read_dir({}) entry failed: {err}", dir.display())))
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("decode_hostile_")
        })
        .count();
    assert!(count >= 15, "KH-GAP-144: floor 15, got {count}");
}
