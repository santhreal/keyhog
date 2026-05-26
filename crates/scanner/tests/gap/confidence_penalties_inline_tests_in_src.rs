//! KH-GAP-012: confidence/penalties.rs still hosts inline tests.

use std::path::PathBuf;

#[test]
fn confidence_penalties_inline_tests_in_src() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/confidence/penalties.rs");
    let src = std::fs::read_to_string(&path).expect("read penalties.rs");
    assert!(
        !src.contains("#[cfg(test)]"),
        "inline NaN-safety tests must live under tests/unit/"
    );
}
