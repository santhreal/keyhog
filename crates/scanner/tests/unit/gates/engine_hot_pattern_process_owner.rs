//! Gate `engine::hot_patterns`: canonical hot-pattern hits must route through
//! the shared `process_match` adjudicator after the SIMD literal and precise
//! regex validator.

use std::path::{Path, PathBuf};

fn scanner_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{} not readable: {e}", path.display()))
}

fn uncommented_code(src: &str) -> String {
    src.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                None
            } else {
                Some(line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn canonical_hot_patterns_delegate_to_process_match() {
    let src = scanner_src();
    let hot_patterns = uncommented_code(&read(&src.join("engine/hot_patterns.rs")));
    let compile = uncommented_code(&read(&src.join("engine/compile.rs")));
    let backend_triggered = uncommented_code(&read(&src.join("engine/backend_triggered.rs")));

    assert!(
        hot_patterns.contains("self.hot_ac_map_index_by_index[pattern_idx]")
            && hot_patterns.contains("hot_pattern_direct_emit_allowed(pattern_idx)")
            && hot_patterns.contains("if ac_map_index.is_none() && !hot_pattern_direct_emit_allowed(pattern_idx)")
            && hot_patterns.contains("self.process_match(")
            && hot_patterns.contains("super::scan_filters::compute_pattern_signals("),
        "canonical hot-pattern hits must delegate through process_match with shared confidence/suppression signals"
    );
    assert!(
        !hot_patterns.contains("self.hot_ac_map_index_by_index.get(pattern_idx)")
            && !hot_patterns.contains("self.hot_pattern_validators.get(pattern_idx)"),
        "hot-pattern runtime tables must be construction-validated and indexed directly, not silently treated as missing slots"
    );
    assert!(
        compile.contains("fn build_hot_ac_map_index_by_index(")
            && compile.contains("crate::compiler::compiler_prefix::extract_literal_prefixes("),
        "compile must build hot-slot to canonical ac_map entries from existing compiler prefix extraction"
    );
    assert!(
        compile.contains("validate_hot_pattern_runtime_table_lengths("),
        "scanner construction must fail loud if hot-pattern runtime tables drift from HOT_PATTERNS"
    );
    let simdsieve = uncommented_code(&read(&src.join("simdsieve_prefilter.rs")));
    assert!(
        simdsieve.contains("fn hot_pattern_direct_emit_allowed(")
            && simdsieve.contains("HOT_PATTERN_DETECTOR_IDS[slot] == crate::detector_ids::HOT_SQUARE_SECRET"),
        "the prefilter table owner must be the only place that allows synthetic direct hot-pattern emission"
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
