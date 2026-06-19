//! Gate `alphabet_filter`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn alphabet_filter_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/alphabet_filter.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "alphabet_filter: move inline tests to crates/scanner/tests/"
    );
}
