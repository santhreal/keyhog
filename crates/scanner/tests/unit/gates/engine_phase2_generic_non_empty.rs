//! Gate `engine::phase2_generic`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn engine_phase2_generic_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/phase2_generic.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    assert!(
        src.trim().len() >= 20,
        "engine::phase2_generic: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "engine::phase2_generic: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        src.contains("line_at_index(scan_text, line_offsets, line_idx)")
            && src.contains("let mut code_lines_cache: Option<Vec<&str>> = None;")
            && src.contains("get_or_insert_with(|| scan_text.lines().collect())"),
        "engine::phase2_generic: generic assignment scanning must slice keyword-hit lines and lazily materialize context lines"
    );
    assert!(
        !src.contains("let code_lines: Vec<&str> = scan_text.lines().collect();"),
        "engine::phase2_generic: generic assignment scanning must not eagerly collect every line before keyword filtering"
    );
}
