//! KH-GAP-011: lib.rs must not duplicate the Santh lint preamble block.

#[test]
fn lib_rs_has_single_lint_preamble_block() {
    let lib_rs = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    ).expect("read lib.rs");
    let count = lib_rs.matches("#![cfg_attr(").count();
    assert_eq!(count, 1, "expected exactly one cfg_attr lint block, found {count}");
}
