//! Gate `context::false_positive`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn context_false_positive_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/context/false_positive.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "context::false_positive: move inline tests to crates/scanner/tests/"
    );
}
