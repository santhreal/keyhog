//! Static fail-closed guard: the coalesced no-hit admission gate must consult the
//! real active phase-2 set, so a chunk that fires no Hyperscan literal but does
//! activate an anchorless / keyword-less fallback detector (asana-pat and ~3100
//! similar, issue #69) is still driven through phase 2 — regardless of whether the
//! triggers were produced by the CPU Hyperscan prefilter or the GPU megakernel.
//!
//! Both producers feed the SHARED `scan_coalesced_phase2`, whose no-hit branch
//! calls `should_scan_no_hit_chunk`, which in turn calls the real
//! `has_active_phase2_patterns_for_chunk` prefilter. The old per-backend
//! `gpu_phase2.rs` gate was unified into this shared tail; this guard tracks the
//! invariant at its new home so a refactor can't silently drop the recall gate
//! (Law 10). Behavioural proof of backend-invariance lives in
//! `megakernel_cpu_parity.rs` / `backend_parity_coalesced_vs_individual.rs`.

use std::fs;
use std::path::PathBuf;

fn scanner_source(path: &str) -> String {
    let mut full = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    full.push("src");
    full.push(path);
    fs::read_to_string(full).expect("read scanner source")
}

#[test]
fn no_hit_admission_consults_active_fallback_set() {
    let scan = scanner_source("engine/scan_coalesced.rs");

    // The shared no-hit admission gate must consult the real active phase-2 set
    // FIRST (the exact, cheap necessary condition for an anchorless match).
    assert!(
        scan.contains("self.has_active_phase2_patterns_for_chunk(&chunk.data)"),
        "should_scan_no_hit_chunk must probe the active phase-2 set to preserve \
         prefixless / keyword-less detector recall on no-literal chunks"
    );

    // The shared coalesced phase-2 tail — fed by BOTH the CPU Hyperscan prefilter
    // and the GPU megakernel — must route no-trigger chunks through that gate.
    assert!(
        scan.contains("if !self.should_scan_no_hit_chunk(chunk)"),
        "scan_coalesced_phase2's no-hit branch must gate on should_scan_no_hit_chunk \
         so CPU and GPU producers share one recall-load-bearing admission policy"
    );

    // The active-set probe must stay shared with the production fallback scanner.
    // The phase-2 scan impl was split out of the old fallback module into
    // `phase2_compiled.rs` under the 500-LOC ceiling (Law 5); the probe now
    // lives there, still `pub(crate)` and still the one the no-hit gate calls.
    let phase2 = scanner_source("engine/phase2_compiled.rs");
    assert!(
        phase2.contains("pub(crate) fn has_active_phase2_patterns_for_chunk"),
        "phase-2 active-set probe must stay shared with the production phase-2 scanner"
    );
}
