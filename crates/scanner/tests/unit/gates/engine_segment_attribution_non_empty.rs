//! Gate `engine::segment_attribution`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn engine_segment_attribution_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/segment_attribution.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "engine::segment_attribution: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "engine::segment_attribution: todo!/unimplemented! forbidden in non-test source"
    );
}
