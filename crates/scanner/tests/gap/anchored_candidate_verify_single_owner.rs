//! Regression: the anchored-candidate verify loop has ONE owner.
//!
//! `scan_phase2_with_anchors` verifies anchored `(pattern, pos)` candidates in
//! two passes: the main shared-anchor candidates and the localized-homoglyph
//! plain candidates. Both ran a byte-identical loop — group a pattern's
//! contiguous candidate run, then either `extract_anchored` (when the anchored
//! regex compiled) or fall back to the cursor-bounded `extract_matches_inner`,
//! with per-pattern profiling. Two copies of the anchored-vs-fallback verify
//! logic is a drift hazard: a change to one pass's fallback (or its profiling)
//! that misses the other silently diverges recall between the two. They are now
//! one `verify_anchored_candidates` helper.
//!
//! This pins the dedup: the helper exists, both passes delegate to it, and the
//! `anchor_idx.anchored_regex(pat)` dispatch survives in exactly one place.

fn read_src(rel: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(root.join(rel)).expect("source file readable")
}

#[test]
fn anchored_candidate_verify_loop_has_single_owner() {
    let src = read_src("src/engine/phase2_compiled_anchored.rs");

    assert!(
        src.contains("fn verify_anchored_candidates"),
        "the anchored-candidate verify loop must live in one owner"
    );

    // Both passes (main + homoglyph) delegate to the helper (`.method(` excludes
    // the `fn ` definition).
    let delegations = src.matches(".verify_anchored_candidates(").count();
    assert_eq!(
        delegations, 2,
        "both anchored-candidate passes must call the helper, found {delegations}"
    );

    // The anchored-vs-fallback dispatch was open-coded in both passes; it must
    // now appear exactly once (inside the helper).
    let dispatch_sites = src.matches("match anchor_idx.anchored_regex(pat)").count();
    assert_eq!(
        dispatch_sites, 1,
        "the anchored_regex dispatch must be deduped into one site, found {dispatch_sites}"
    );
}
