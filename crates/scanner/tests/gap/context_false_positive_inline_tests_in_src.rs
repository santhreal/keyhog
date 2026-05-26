//! KH-GAP-011: context/false_positive.rs still hosts inline tests.

use std::path::PathBuf;

#[test]
fn context_false_positive_inline_tests_in_src() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/context/false_positive.rs");
    let src = std::fs::read_to_string(&path).expect("read false_positive.rs");
    assert!(
        !src.contains("#[cfg(test)]"),
        "inline tests must migrate to tests/unit/ per Santh folder contract"
    );
}
