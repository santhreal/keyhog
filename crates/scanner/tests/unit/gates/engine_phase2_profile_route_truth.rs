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

    // The profile runtime owns the mark counters: every record_* must be a
    // typed-counter add with its exact registry ID, and the drain-based reader
    // must build the snapshot from one take_typed_metrics batch.
    for (record_fn, counter) in [
        ("record_mark_call", "Phase2PrefilterMarkCalls"),
        ("record_mark_gate_skip", "Phase2PrefilterGateSkips"),
        ("record_mark_perpattern_work", "Phase2PrefilterPerPatternWork"),
        ("record_mark_hs_served", "Phase2PrefilterHsServed"),
        ("record_mark_regexset_served", "Phase2PrefilterRegexsetServed"),
    ] {
        assert!(
            mark_stats.contains(&format!("fn {record_fn}"))
                && mark_stats.contains(&format!("CounterId::{counter}")),
            "{record_fn} must record through keyhog_profile::add_counter(CounterId::{counter})"
        );
    }
    assert!(
        !mark_stats.contains("AtomicU64"),
        "mark stats must not keep its own atomic counters; the profile runtime owns them"
    );
    assert!(
        mark_stats.contains("fn mark_snapshot_from_typed"),
        "the mark snapshot must be built from the drained typed-metric batch"
    );
    assert!(
        phase2.contains("mark_snapshot_from_typed, record_mark_call"),
        "engine phase2 owner must re-export the typed-counter mark API"
    );
    // profile::reset must reach the typed-counter store (keyhog_profile::reset
    // clears it) so each report reflects only its own run.
    assert!(
        profile.contains("keyhog_profile::reset();"),
        "scan_profile::reset must clear the profile runtime (incl. mark stats) between explicit profile runs"
    );
}
