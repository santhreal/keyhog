//! Gate `engine::windowed`: substantive source, no todo!/unimplemented! in prod paths.

#[test]
fn engine_windowed_non_empty() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/windowed.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let coalesced_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/scan_coalesced.rs");
    let coalesced_src = std::fs::read_to_string(coalesced_path).expect("coalesced source readable");
    assert!(
        src.trim().len() >= 20,
        "engine::windowed: expected substantive source, got {} trimmed bytes",
        src.trim().len()
    );
    let prod = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !prod.contains("todo!()") && !prod.contains("unimplemented!()"),
        "engine::windowed: todo!/unimplemented! forbidden in non-test source"
    );
    assert!(
        src.contains("pub(crate) fn scan_windowed_with_triggered")
            && src.contains("triggered_patterns: &[u64]")
            && src.contains("scan_prepared_with_triggered("),
        "engine::windowed: coalesced/GPU large-chunk phase-2 must preserve producer trigger bitmaps instead of recomputing phase1 per window"
    );
    assert!(
        !src.contains("scan_chunk_or_window"),
        "engine::windowed: do not reintroduce the wrapper that discarded coalesced producer triggers on large chunks"
    );
    assert!(
        coalesced_src.contains("self.scan_windowed_with_triggered(")
            && coalesced_src.contains("keyword_hints")
            && coalesced_src.contains("always_anchor_present"),
        "engine::scan_coalesced: triggered large chunks must route through scan_windowed_with_triggered with producer keyword hints and always-anchor presence proof"
    );
}
