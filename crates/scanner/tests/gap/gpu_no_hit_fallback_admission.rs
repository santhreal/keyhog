use std::fs;
use std::path::PathBuf;

fn scanner_source(path: &str) -> String {
    let mut full = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    full.push("src");
    full.push(path);
    fs::read_to_string(full).expect("read scanner source")
}

#[test]
fn gpu_no_hit_chunks_consult_active_fallback_set() {
    let phase2 = scanner_source("engine/gpu_phase2.rs");
    assert!(
        phase2.contains("has_active_fallback_patterns_for_chunk(&chunk.data)"),
        "GPU no-hit phase2 admission must preserve prefixless fallback detector recall"
    );

    let fallback = scanner_source("engine/fallback.rs");
    assert!(
        fallback.contains("pub(crate) fn has_active_fallback_patterns_for_chunk"),
        "fallback active-set probe must stay shared with the production fallback scanner"
    );
}
