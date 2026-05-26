//! Gate `ml_features`: modularity file cap (500 LOC).

#[test]
fn ml_features_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/ml_features.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    assert!(
        lines <= 500,
        "ml_features: {lines} lines exceeds 500-line cap — split module"
    );
}
