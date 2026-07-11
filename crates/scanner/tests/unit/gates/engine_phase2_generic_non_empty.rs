//! Gate `engine::phase2_generic`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn engine_phase2_generic_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/phase2_generic.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let keywords_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/phase2_generic/keywords.rs"
    );
    let keywords_src = std::fs::read_to_string(keywords_path).expect("keywords source readable");
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
            && src.contains("preprocessed_code_lines_cache: Option<Vec<&str>>")
            && src.contains("preprocessed_documentation_lines_cache: Option<Vec<bool>>")
            && src.contains("get_or_insert_with(|| scan_text.lines().collect())"),
        "engine::phase2_generic: generic assignment scanning must slice keyword-hit lines and lazily materialize synthesized context lines"
    );
    assert!(
        !src.contains("let code_lines: Vec<&str> = scan_text.lines().collect();"),
        "engine::phase2_generic: generic assignment scanning must not eagerly collect every line before keyword filtering"
    );
    assert!(
        src.contains("infer_context_with_documentation(") && !src.contains("crate::context::infer_context("),
        "engine::phase2_generic: generic context inference must reuse precomputed documentation flags instead of rebuilding them per candidate"
    );
    assert!(
        src.contains("collect_generic_keyword_lines_with_stems(")
            && src.contains("&self.generic_assignment.stems")
            && src.contains("collect_generic_keyword_lines_from_positions(")
            && keywords_src.contains("collect_generic_keyword_lines_from_positions")
            && keywords_src.contains("generic_keyword_prefilter_stems_for(")
            && !src.contains("GENERIC_BRIDGE_EXTRA_KEYWORDS")
            && !src.contains(".chain(GENERIC_BRIDGE_EXTRA_KEYWORDS.iter())"),
        "engine::phase2_generic: generic keyword prefilter must use the derived compact stem collector and the trusted GPU-position input mode, not the full spelling list"
    );
}
