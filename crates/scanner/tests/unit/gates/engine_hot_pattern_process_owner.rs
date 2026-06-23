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
        hot_patterns.contains("self.hot_ac_map_index_by_index.get(pattern_idx)")
            && hot_patterns.contains("self.process_match(")
            && hot_patterns.contains("super::scan_filters::compute_pattern_signals("),
        "canonical hot-pattern hits must delegate through process_match with shared confidence/suppression signals"
    );
    assert!(
        compile.contains("fn build_hot_ac_map_index_by_index(")
            && compile.contains("crate::compiler::compiler_prefix::extract_literal_prefixes("),
        "compile must build hot-slot to canonical ac_map entries from existing compiler prefix extraction"
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
