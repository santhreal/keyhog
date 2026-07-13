//! SWE-101 regression gate: the `mark_matches` no-candidate gate path must be
//! well below the 30931 ns/call pre-fix baseline.
//!
//! **Background**: before the combined no-candidate gate was added, every
//! `mark_matches` call ran the full Hyperscan always-active prefilter scan
//! (~30931 ns/call) even on pure no-candidate chunks. The gate (`CombinedNoCandidateGate`)
//! short-circuits at one exact first-bigram pass + one AC `is_match`, skipping the
//! expensive per-pattern body entirely on chunks that cannot activate any
//! always-active pattern.
//!
//! **This test** measures the ISOLATED `mark_matches` gate path cost, bypassing
//! the phase-1 Hyperscan scan entirely, by calling the internal timing helper
//! `testing::mark_matches_gate_ns_per_call`. It asserts the per-call cost is
//! well below 30931 ns (the concrete pre-fix ceiling from the issue), proving
//! the optimization closes the gap by an order of magnitude.
//!
//! The test is **not** a whole-pipeline benchmark (that is
//! `phase2_prefilter_cost_target_spec`); it pins only the isolated gate path.
//!
//! Run (release mode for meaningful ns-scale numbers):
//!   cargo test -p keyhog-scanner --no-default-features --features simd --release \
//!     --test phase2_no_candidate_gate_perf -- --nocapture

use super::support;
use support::paths::detector_dir;

/// Isolated `mark_matches` gate path cost ceiling. The pre-fix always-active HS
/// scan cost 30931 ns/call. The first-bigram+AC gate must be at least 10x cheaper
/// this ceiling is 3000 ns, leaving 10x headroom below the pre-fix baseline.
/// On Zen 4 / warm L1d the gate typically costs 100-600 ns for ~200-byte
/// no-candidate text.
const GATE_CEILING_NS: f64 = 3_000.0;

/// Iterations for the timed loop (enough to amortise timer overhead and
/// OS scheduling noise, small enough to complete in a few hundred ms).
const N_CALLS: u32 = 50_000;

/// No-candidate text: pure whitespace (spaces, tabs, newlines only) under the
/// chunk-bigram threshold (< 64 bytes so the chunk pre-screen is bypassed
/// and the scan always reaches `mark_matches`). No 3-byte substring can match
/// any credential prefix literal (which is always pure ASCII non-whitespace), so
/// the combined gate is GUARANTEED to skip on every call regardless of which
/// literals the gate was built from. This matches the `NO_CANDIDATE_TEXT` pattern
/// used in `phase2_no_candidate_zero_work`.
const NO_CANDIDATE_TEXT: &str =
    "\n    \t  \n        \n  \t\t  \n   \n      \n  \n        \n   \t \n  \n";

#[test]
fn mark_matches_gate_path_is_fast() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors unavailable: {e}");
            return;
        }
    };
    let scanner =
        keyhog_scanner::CompiledScanner::compile(detectors).expect("scanner compile failed");

    // Ensure the no-candidate gate is ON (the default).
    keyhog_scanner::testing::set_no_candidate_gate(&scanner, Some(true));

    // Warm: reset counters and verify the gate fires on one scan, so the timed
    // loop starts with the gate path warm.
    crate::engine::phase2_mark_stats_reset();
    {
        use keyhog_core::{Chunk, ChunkMetadata};
        let chunk = Chunk {
            data: NO_CANDIDATE_TEXT.to_string().into(),
            metadata: ChunkMetadata {
                source_type: "gate-perf-warm".into(),
                ..Default::default()
            },
        };
        let _ = scanner.scan(&chunk);
    }
    let warm = crate::engine::phase2_mark_stats();
    let (warm_calls, warm_skips, warm_work) = (warm.calls, warm.gate_skips, warm.perpattern_work);
    assert!(
        warm_calls >= 1,
        "warm scan: mark_matches must be invoked (calls={warm_calls})"
    );
    assert_eq!(
        warm_work, 0,
        "SWE-101 REGRESSION: no-candidate warm scan did {warm_work} per-pattern work calls \
         (calls={warm_calls}, skips={warm_skips}). The combined gate must be active."
    );
    assert_eq!(
        warm_skips, warm_calls,
        "warm scan: every call must be a gate skip on no-candidate text \
         (skips={warm_skips}, calls={warm_calls})"
    );

    if cfg!(debug_assertions) {
        eprintln!(
            "SWE-101 debug profile verified zero per-pattern work; run this test with --release \
             for the {GATE_CEILING_NS:.0} ns/call perf ceiling"
        );
        return;
    }

    // Timed loop: call mark_matches directly N times, bypassing the phase-1 HS
    // scan so only the gate path is measured.
    let ns_per_call = keyhog_scanner::testing::mark_matches_gate_ns_per_call(
        &scanner,
        NO_CANDIDATE_TEXT,
        N_CALLS,
    );

    eprintln!(
        "SWE-101 isolated mark_matches gate cost: {ns_per_call:.1} ns/call \
         (pre-fix baseline: 30931 ns, ceiling: {GATE_CEILING_NS:.0} ns, n={N_CALLS})"
    );

    // Concrete ceiling: at least 10x below the pre-fix 30931 ns/call baseline.
    assert!(
        ns_per_call < GATE_CEILING_NS,
        "SWE-101 REGRESSION: mark_matches gate path costs {ns_per_call:.1} ns/call on \
         no-candidate text, which exceeds the {GATE_CEILING_NS:.0} ns ceiling \
         (pre-fix baseline was 30931 ns/call, the gate is 10x cheaper or the \
         optimization was reverted). Fix the gate path cost."
    );
}
