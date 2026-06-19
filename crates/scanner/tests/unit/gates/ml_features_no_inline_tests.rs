//! Gate `ml_features`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn ml_features_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/ml_scorer/ml_features.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !super::inline_gate::contains_inline_test_module_or_function(&src),
        "ml_features: move inline tests to crates/scanner/tests/"
    );
}
