//! KH-GAP-015: compiler_prefix.rs still hosts inline inner-literal tests.

use std::path::PathBuf;

#[test]
fn compiler_prefix_inline_tests_in_src() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src/compiler_prefix.rs");
    let src = std::fs::read_to_string(&path).expect("read compiler_prefix.rs");
    assert!(
        !src.contains("#[cfg(test)]"),
        "inner literal corpus tests must migrate to tests/unit/"
    );
}
