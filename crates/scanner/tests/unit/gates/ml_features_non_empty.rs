//! Gate `ml_features`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn ml_features_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/ml_features.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "ml_features: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "ml_features: todo!/unimplemented! forbidden in non-test source"
    );
}
