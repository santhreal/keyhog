//! Gate `multiline::preprocessor`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn multiline_preprocessor_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/multiline/preprocessor.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "multiline::preprocessor: move inline tests to crates/scanner/tests/"
    );
}
