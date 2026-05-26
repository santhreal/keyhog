//! Gate `engine::boundary`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn engine_boundary_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/boundary.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "engine::boundary: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "engine::boundary: todo!/unimplemented! forbidden in non-test source"
    );
}
