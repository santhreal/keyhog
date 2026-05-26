//! Gate `engine::fallback_entropy`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn engine_fallback_entropy_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/fallback_entropy.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "engine::fallback_entropy: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "engine::fallback_entropy: todo!/unimplemented! forbidden in non-test source"
    );
}
