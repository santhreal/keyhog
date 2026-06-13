//! Gate `ml_features`: no inline #[cfg(test)] (Santh folder contract).

#[test]
fn ml_features_no_inline_tests() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/ml_scorer/ml_features.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        !src.contains("#[cfg(test)]"),
        "ml_features: move inline tests to crates/scanner/tests/"
    );
}
