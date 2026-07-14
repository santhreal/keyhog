//! Gate `engine::hot_patterns`: canonical hot-pattern hits must route through
//! the shared `process_match` adjudicator after the SIMD literal and precise
//! regex validator.

use super::support::*;

#[test]
fn canonical_hot_patterns_delegate_to_process_match() {
    let src = scanner_src();
    let hot_patterns = uncommented_code(&read(&src.join("engine/hot_patterns.rs")));
    let compile = uncommented_code(&read(&src.join("compiled_scanner/compile.rs")));
    let compile_helpers = uncommented_code(&read(&src.join("compiled_scanner/compile_helpers.rs")));
    let backend_triggered = uncommented_code(&read(&src.join("engine/backend_triggered.rs")));

    assert!(
        hot_patterns.contains("let slot = &self.hot_pattern_slots[pattern_idx];")
            && hot_patterns.contains("let ac_map_index = slot.ac_map_index;")
            && hot_patterns.contains("match slot.validator.find(credential)")
            && hot_patterns.contains("self.process_match(")
            && hot_patterns.contains("super::scan_filters::compute_pattern_signals("),
        "canonical hot-pattern hits must resolve one unified slot (validator + ac_map delegate \
         indexed together, never apart) and delegate through process_match with shared \
         confidence/suppression signals"
    );
    for forbidden in [
        "hot_pattern_direct_emit_allowed",
        "push_match_lazy",
        "build_synthetic_raw_match",
        "hot_metadata_by_index",
        "hot_pattern_confidence",
        "hot_pattern_suppression_stage",
    ] {
        assert!(
            !hot_patterns.contains(forbidden),
            "hot-pattern fast path must not own synthetic direct-emission token {forbidden:?}"
        );
    }
    assert!(
        !hot_patterns.contains("self.hot_pattern_slots.get(pattern_idx)"),
        "the unified hot-pattern slot table must be construction-validated and indexed directly, not silently treated as a missing slot via .get()"
    );
    assert!(
        compile.contains("build_hot_pattern_slots(")
            && compile_helpers.contains("fn build_hot_pattern_slots(")
            && compile_helpers.contains("simdsieve_prefixes")
            && compile_helpers
                .contains("crate::compiler::compiler_prefix::extract_literal_prefixes("),
        "compile must build hot-pattern slots from detector-owned declarations and resolve each slot through existing compiler prefix extraction"
    );
    assert!(
        compile_helpers.contains("if total > 16")
            && compile_helpers.contains("declared by more than one loaded detector")
            && compile_helpers.contains("none of its compiled patterns exposes"),
        "the slot builder must fail loud on backend capacity, duplicate ownership, and unbacked detector declarations"
    );
    let simdsieve = uncommented_code(&read(&src.join("simdsieve_prefilter.rs")));
    assert!(
        !simdsieve.contains("fn hot_pattern_direct_emit_allowed(")
            && !simdsieve.contains("HOT_SQUARE_SECRET"),
        "the prefilter table owner must not expose a synthetic direct hot-pattern emission switch"
    );
    assert!(
        backend_triggered
            .contains("let documentation_lines = context::documentation_line_flags(&code_lines);")
            && backend_triggered.contains("&documentation_lines,")
            && backend_triggered
                .find("documentation_line_flags")
                .unwrap_or(usize::MAX)
                < backend_triggered
                    .find("scan_hot_patterns_fast(")
                    .unwrap_or(0),
        "hot-pattern scan must receive documentation-line context before it runs"
    );
}
