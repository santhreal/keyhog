#[test]
fn phase2_portable_regexset_prefilter_is_lazy() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let phase2 =
        std::fs::read_to_string(root.join("src/engine/phase2.rs")).expect("phase2 source readable");
    let prefilter = std::fs::read_to_string(root.join("src/engine/phase2_prefilter.rs"))
        .expect("phase2_prefilter source readable");

    assert!(
        phase2.contains("pub(crate) struct PortablePrefilter")
            && phase2.contains("pub(crate) portable: OnceLock<PortablePrefilter>")
            && phase2.contains("pub(crate) valid_always_active_indices: Vec<usize>"),
        "Phase2AlwaysActivePrefilter must store only lightweight routing state eagerly and keep portable RegexSet batches behind OnceLock"
    );

    let build_body = prefilter
        .split("pub(crate) fn build(")
        .nth(1)
        .expect("build present")
        .split("fn portable")
        .next()
        .expect("build boundary present");
    for forbidden in [
        "let mut batches = Vec::new()",
        "Self::build_partition(",
        "Self::build_batches(",
        "compile_set(",
        "RegexSetBuilder::new",
    ] {
        assert!(
            !build_body.contains(forbidden),
            "Phase2AlwaysActivePrefilter::build must not compile portable RegexSet state eagerly: {forbidden}"
        );
    }

    assert!(
        prefilter.contains(".get_or_init(|| self.compile_portable(phase2_patterns))")
            && prefilter.contains("fn compile_portable(")
            && prefilter.contains("Self::build_partition("),
        "portable RegexSet batches must compile through a single lazy OnceLock owner"
    );

    let mark_body = prefilter
        .split("pub(crate) fn mark_matches(")
        .nth(1)
        .expect("mark_matches present")
        .split("pub(crate) fn any_active_match(")
        .next()
        .expect("mark_matches boundary present");
    let hs_pos = mark_body
        .find("if let Some(hs) = &self.hs")
        .expect("HS fast path present");
    let portable_pos = mark_body
        .find("let portable = self.portable(phase2_patterns);")
        .expect("portable lazy init present in mark_matches");
    assert!(
        hs_pos < portable_pos,
        "mark_matches must try no-candidate/HS paths before initializing portable RegexSet batches"
    );

    let any_body = prefilter
        .split("pub(crate) fn any_active_match(")
        .nth(1)
        .expect("any_active_match present");
    let hs_any_pos = any_body
        .find("if let Some(hs) = &self.hs")
        .expect("HS admission path present");
    let portable_any_pos = any_body
        .find("let portable = self.portable(phase2_patterns);")
        .expect("portable lazy init present in any_active_match");
    assert!(
        hs_any_pos < portable_any_pos,
        "any_active_match must use exact HS admission before initializing portable RegexSet batches"
    );
}
