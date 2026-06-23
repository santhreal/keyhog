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
            && phase2.contains("pub(crate) combined_gate: OnceLock<Option<CombinedNoCandidateGate>>")
            && phase2.contains("pub(crate) hs: OnceLock<Option<Phase2HsEngine>>")
            && phase2.contains("pub(crate) valid_always_active_indices: Vec<usize>"),
        "Phase2AlwaysActivePrefilter must store only lightweight routing state eagerly and keep portable RegexSet/HS/AC gate state behind OnceLock"
    );

    let build_body = prefilter
        .split("pub(crate) fn build(")
        .nth(1)
        .expect("build present")
        .split("fn combined_gate")
        .next()
        .expect("build boundary present");
    for forbidden in [
        "let mut batches = Vec::new()",
        "Self::build_partition(",
        "Self::build_batches(",
        "compile_set(",
        "RegexSetBuilder::new",
        "Phase2HsEngine::build(",
        "Self::build_combined_gate(",
    ] {
        assert!(
            !build_body.contains(forbidden),
            "Phase2AlwaysActivePrefilter::build must not compile heavy prefilter state eagerly: {forbidden}"
        );
    }

    assert!(
        prefilter.contains(".get_or_init(|| self.compile_portable(phase2_patterns))")
            && prefilter.contains("fn compile_portable(")
            && prefilter.contains("Self::build_partition("),
        "portable RegexSet batches must compile through a single lazy OnceLock owner"
    );
    assert!(
        prefilter.contains("fn combined_gate<'a>(")
            && prefilter.contains(
                "Self::build_combined_gate(phase2_patterns, &self.valid_always_active_indices)"
            ),
        "phase-2 no-candidate AC gate must compile through a single lazy OnceLock owner"
    );
    assert!(
        prefilter.contains("fn hs<'a>(")
            && prefilter.contains(".get_or_init(|| {\n                Phase2HsEngine::build(phase2_patterns, &self.valid_always_active_indices)\n            })"),
        "phase-2 HS prefilter must compile through a single lazy OnceLock owner"
    );

    let mark_body = prefilter
        .split("pub(crate) fn mark_matches(")
        .nth(1)
        .expect("mark_matches present")
        .split("pub(crate) fn any_active_match(")
        .next()
        .expect("mark_matches boundary present");
    let hs_pos = mark_body
        .find("if let Some(hs) = self.hs(phase2_patterns)")
        .expect("HS fast path present");
    let portable_pos = mark_body
        .find("let portable = self.portable(phase2_patterns);")
        .expect("portable lazy init present in mark_matches");
    let no_candidate_pos = mark_body
        .find("if let Some(gate) = self.combined_gate(phase2_patterns)")
        .expect("no-candidate gate present");
    assert!(
        no_candidate_pos < hs_pos && hs_pos < portable_pos,
        "mark_matches must try no-candidate, then lazy HS, before initializing portable RegexSet batches"
    );

    let any_body = prefilter
        .split("pub(crate) fn any_active_match(")
        .nth(1)
        .expect("any_active_match present");
    let hs_any_pos = any_body
        .find("if let Some(hs) = self.hs(phase2_patterns)")
        .expect("HS admission path present");
    let portable_any_pos = any_body
        .find("let portable = self.portable(phase2_patterns);")
        .expect("portable lazy init present in any_active_match");
    let no_candidate_any_pos = any_body
        .find("if tuning.no_candidate_gate")
        .expect("no-candidate admission gate present");
    assert!(
        no_candidate_any_pos < hs_any_pos && hs_any_pos < portable_any_pos,
        "any_active_match must use no-candidate, then exact lazy HS admission before initializing portable RegexSet batches"
    );
}
