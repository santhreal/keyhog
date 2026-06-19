//! KH-GAP-160: Reverse adversarial files beyond unit/scanner_misc.

use std::path::PathBuf;

#[test]
fn r5_reverse_beyond_unit_misc() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial/reverse");
    let count = std::fs::read_dir(&dir)
        .expect("reverse")
        .map(|e| e.unwrap_or_else(|err| panic!("read_dir({}) entry failed: {err}", dir.display())))
        .filter(|e| e.file_name().to_string_lossy().starts_with("reverse_"))
        .count();
    assert!(
        count >= 6,
        "KH-GAP-160: reverse adversarial floor, got {count}"
    );
}
