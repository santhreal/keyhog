//! Regression: the whole-chunk phase-2 extraction loop has ONE owner.
//!
//! `scan_phase2_patterns` (small chunks) and `scan_large_phase2_patterns` (large
//! chunks) both walk the sparse active phase-2 set, running each pattern's
//! `extract_matches` under the same `is_multiple_of(16)` deadline cadence and the
//! same per-pattern profiling. Those were two byte-identical copies of that loop:
//! a drift hazard where, e.g., changing the abort cadence on one path but not the
//! other makes `--timeout` behave differently by chunk size. They are now one
//! `extract_active_phase2_patterns` helper.
//!
//! The decode-focus path (`scan_phase2_patterns_focused`) keeps its own loop on
//! purpose, it is cursor-bounded via `extract_matches_inner`, a real difference,
//! not duplication.
//!
//! This pins the dedup: the helper exists, both whole-chunk paths delegate to it,
//! and the bare `extract_matches(` whole-chunk call survives in exactly one place.

fn read_src(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect("source file readable")
}

#[test]
fn whole_chunk_phase2_extract_loop_has_single_owner() {
    let src = read_src("src/engine/phase2_compiled.rs");

    assert!(
        src.contains("fn extract_active_phase2_patterns"),
        "the whole-chunk phase-2 extraction loop must live in one owner"
    );

    // Both whole-chunk closures delegate to the helper (`.method(` excludes the
    // `fn ` definition, which has no leading dot).
    let delegations = src.matches(".extract_active_phase2_patterns(").count();
    assert_eq!(
        delegations, 2,
        "both whole-chunk closures must call the helper, found {delegations}"
    );

    // The deadline-cadence loop was open-coded three times: the two whole-chunk
    // paths (now collapsed into the helper) and the decode-focus path (kept,
    // cursor-bounded). So the cadence marker must drop from 3 sites to 2 (helper
    // + focus) (proving the two whole-chunk copies became one).
    let cadence_sites = src.matches("tested.is_multiple_of(16)").count();
    assert_eq!(
        cadence_sites, 2,
        "the deadline-cadence loop must exist in exactly 2 sites (helper + focus), found {cadence_sites}"
    );

    assert!(
        src.contains("extract_matches_inner("),
        "the decode-focus path keeps its own cursor-bounded extract_matches_inner loop"
    );
}
