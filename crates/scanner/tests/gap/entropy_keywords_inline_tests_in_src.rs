//! KH-GAP-013: entropy/keywords.rs still hosts inline identifier tests.

use std::path::PathBuf;

#[test]
fn entropy_keywords_inline_tests_in_src() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/entropy/keywords.rs");
    let src = std::fs::read_to_string(&path).expect("read keywords.rs");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "identifier rejection tests must migrate out of src/"
    );
}
