//! Gate `engine::phase2_compiled`: phase-2 profile route labels must describe
//! compiled anchor eligibility separately from looser parser-only prefix shape.

#[test]
fn engine_phase2_profile_route_truth() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/phase2_compiled.rs");
    let src = std::fs::read_to_string(path).expect("phase2_compiled source readable");
    assert!(
        src.contains("idx.is_eligible(*i)")
            && src.contains("[ELIG]=compiled shared-anchor eligible")
            && src.contains("[PREFIX]=prefix-shaped but not anchor-eligible in this scanner"),
        "phase2 profile must label compiled shared-anchor eligibility separately from prefix shape"
    );
    assert!(
        !src.contains("if anchored { \"ANCHOR\" }") && !src.contains("[LOCAL]"),
        "phase2 profile must not report parser-only prefix shape or cutoff-limited eligibility as a guaranteed LOCAL route"
    );
}

#[test]
fn engine_profile_reset_clears_phase2_mark_stats() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mark_stats = std::fs::read_to_string(root.join("src/engine/phase2/mark_stats.rs"))
        .expect("phase2 mark stats source readable");
    let phase2 =
        std::fs::read_to_string(root.join("src/engine/phase2.rs")).expect("phase2 source readable");
    let profile = std::fs::read_to_string(root.join("src/scan_profile.rs"))
        .expect("scan profile source readable");

    assert!(
        mark_stats.contains("#[cfg(not(test))]\npub(crate) fn phase2_mark_stats_reset()")
            && mark_stats.contains("MARK_CALLS.store(0, Relaxed)")
            && mark_stats.contains("MARK_GATE_SKIPS.store(0, Relaxed)")
            && mark_stats.contains("MARK_PERPATTERN_WORK.store(0, Relaxed)")
            && mark_stats.contains("MARK_HS_SERVED.store(0, Relaxed)")
            && mark_stats.contains("MARK_REGEXSET_SERVED.store(0, Relaxed)"),
        "production phase2 mark counters (incl. the HS/RegexSet path split) must \
         all have a real reset, not only a test-only reset"
    );
    assert!(
        phase2.contains("phase2_mark_stats_reset, record_mark_call"),
        "engine phase2 owner must re-export phase2_mark_stats_reset outside cfg(test)"
    );
    assert!(
        profile.contains("crate::engine::phase2::phase2_mark_stats_reset();"),
        "scan_profile::reset must clear phase2 mark stats between explicit profile runs"
    );
}
