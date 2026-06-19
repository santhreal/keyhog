//! KH-GAP-014: compiler.rs still hosts inline alternation tests.

use std::path::PathBuf;

#[test]
fn compiler_inline_tests_in_src() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/compiler.rs");
    let src = std::fs::read_to_string(&path).expect("read compiler.rs");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "compiler alternation rewrite tests must migrate to tests/unit/"
    );
}
