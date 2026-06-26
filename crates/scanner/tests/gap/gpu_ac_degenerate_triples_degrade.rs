//! GPU AC corrupt/degenerate match ranges must be rejected, and every GPU
//! dispatch failure must carry an operator-visible reason — never a silent
//! degrade (Law 10).
//!
//! The 78046450 consolidation removed `engine/gpu_ac_phase1.rs`: GPU phase-1 is
//! now POSITIONLESS (a presence bitmap via `scan_presence` or the coalesced
//! region-presence path — see `backend_triggered.rs` / `gpu_region_dispatch.rs`),
//! and all match POSITIONS come from CPU regex in
//! `scan_coalesced_phase2`. So a degenerate GPU position triple can no longer
//! reach attribution; the surviving structured integrity guard is
//! `segment_attribution::map_offsets_to_segments`, and the surviving degrade
//! contract is the reason-recording `gpu_last_degrade_reason` slot. These tests
//! pin those, behaviorally where possible.

use std::fs;
use std::path::PathBuf;

use keyhog_scanner::testing::segment_attribution::{
    map_offsets_to_segments, GlobalMatch, Segment, SegmentAttributionError,
};

fn engine_src(rel: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{rel} not readable ({e}); path moved - update this gate"))
}

/// Behavioral: a match whose `end <= start` is a corrupt range and MUST be
/// rejected with `InvalidMatchRange`, never silently attributed. This is the
/// integrity guard that the old inline `gpu_ac_phase1` degenerate-triple check
/// became after consolidation - now a fail-closed structured error on the shared
/// offset->segment primitive.
#[test]
fn degenerate_match_ranges_are_rejected_not_silently_attributed() {
    let seg = Segment::new(1, 0, 16); // id 1, [0, 16)
    for (start, end) in [(5u32, 5u32), (8u32, 3u32)] {
        let err = map_offsets_to_segments(&[seg], &[GlobalMatch::new(7, start, end)])
            .expect_err("degenerate range must error");
        assert!(
            matches!(
                err,
                SegmentAttributionError::InvalidMatchRange { start: s, end: e, .. }
                    if s == start && e == end
            ),
            "degenerate range start={start} end={end} must yield InvalidMatchRange, got {err:?}"
        );
    }
    // Control: a well-formed range inside the segment attributes exactly once.
    let ok = map_offsets_to_segments(&[seg], &[GlobalMatch::new(7, 2, 6)])
        .expect("a valid in-segment range must attribute");
    assert_eq!(ok.len(), 1, "expected one attributed match, got {ok:?}");
}

/// Every GPU dispatch failure mode records a CONCRETE reason into
/// `gpu_last_degrade_reason` (operator-visible via `last_gpu_degrade_reason()`
/// and the self-test) — never a bare "GPU unavailable". The reasons live in the
/// two consolidated dispatch sites that replaced `gpu_ac_phase1.rs`.
#[test]
fn gpu_dispatch_failures_preserve_operator_visible_reasons() {
    let dispatch = engine_src("src/engine/gpu_region_dispatch.rs");
    let trigger = engine_src("src/engine/backend_triggered.rs");
    for needle in [
        "gpu literal matcher not built for coalesced region scan",
        "no gpu backend acquired for coalesced region dispatch",
        "region-presence dispatch error: {error}",
        "region-presence readback length mismatch",
    ] {
        assert!(
            dispatch.contains(needle),
            "gpu_region_dispatch degrade must carry a concrete reason: {needle:?}"
        );
    }
    for needle in [
        "gpu literal matcher not built for this scanner",
        "no gpu backend acquired for per-chunk trigger dispatch",
        "gpu presence scan failed: {error}",
    ] {
        assert!(
            trigger.contains(needle),
            "backend_triggered per-chunk GPU degrade must carry a concrete reason: {needle:?}"
        );
    }
    // Both degrade closures funnel the reason into the recorded slot.
    assert!(
        dispatch.contains("self.record_gpu_degrade(reason.clone())"),
        "coalesced GPU degrade must record the reason through the shared GPU degrade owner"
    );
    assert!(
        trigger.contains("self.record_gpu_degrade(reason.clone())"),
        "per-chunk GPU degrade must record the reason through the shared GPU degrade owner"
    );
}

/// The `backend --self-test` JSON must receive the concrete GPU degrade reason
/// through the public `last_gpu_degrade_reason()` accessor, not by scraping
/// stderr. Pins the field -> accessor -> self-test wiring across the consolidated
/// files.
#[test]
fn gpu_self_test_can_report_recorded_degrade_reason() {
    let engine = engine_src("src/engine/mod.rs");
    let api = engine_src("src/engine/compiled_api.rs");
    let gpu_self_test = engine_src("src/gpu/self_test.rs");
    assert!(
        engine.contains("gpu_last_degrade_reason"),
        "engine must hold the gpu_last_degrade_reason slot"
    );
    assert!(
        api.contains("fn last_gpu_degrade_reason"),
        "a public last_gpu_degrade_reason() accessor must expose the recorded reason"
    );
    assert!(
        gpu_self_test.contains("last_gpu_degrade_reason()"),
        "the GPU self-test must read the reason via last_gpu_degrade_reason(), not stderr"
    );
}

/// The stale AC GPU bounded-ranges builder was deleted as a dead route. Keep
/// this gate pointed at the current live invariant, which now spans two files
/// after the lazy/helper split:
///   * `gpu_lazy.rs` owns the lazy-dispatch accessors (`gpu_matcher` /
///     `gpu_position_matcher`) that drive both per-chunk and coalesced GPU
///     trigger production through `compile_gpu_literal_set`, and keeps the old
///     bounded-ranges `ac_gpu_program` documented as a removed dead route.
///   * `gpu_lazy_helpers.rs` owns the actual cache/scratch path
///     (`cached_load_or_compile` → `GpuLiteralSet::compile`) the accessors call.
#[test]
fn gpu_lazy_keeps_removed_ac_program_dead_and_literal_set_live() {
    let lazy = engine_src("src/engine/gpu_lazy.rs");
    assert!(
        lazy.contains("GpuLiteralSet")
            && lazy.contains("compile_gpu_literal_set")
            && lazy.contains("gpu_matcher")
            && lazy.contains("ac_gpu_program")
            && lazy.contains("removed as dead")
            && !lazy.contains("build_ac_bounded_ranges_program_bound_atomic")
            && !lazy.contains("fn append_match_bound_slot"),
        "gpu_lazy.rs must keep the old bounded-ranges AC program dead and expose only the live GpuLiteralSet accessors"
    );

    let helpers = engine_src("src/engine/gpu_lazy_helpers.rs");
    assert!(
        helpers.contains("cached_load_or_compile") && helpers.contains("GpuLiteralSet::compile"),
        "gpu_lazy_helpers.rs must own the live GpuLiteralSet cache/compile path the accessors call"
    );
}
