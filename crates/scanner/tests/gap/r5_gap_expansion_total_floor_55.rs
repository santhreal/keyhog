//! KH-GAP-162: R5 gap rs file total floor.

use std::path::PathBuf;

#[test]
fn r5_gap_expansion_total_floor_55() {
    let gap = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/gap");
    let count = std::fs::read_dir(&gap)
        .expect("gap dir")
        .map(|e| e.unwrap_or_else(|err| panic!("read_dir({}) entry failed: {err}", gap.display())))
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("rs"))
        .filter(|e| e.file_name() != "mod.rs")
        .count();
    assert!(count >= 55, "KH-GAP-162: gap rs floor 55, got {count}");
}
