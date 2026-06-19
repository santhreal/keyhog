//! Autoroute GPU opt-in contract: the pure-fn decision inputs the production
//! router gates on (TESTING vector 12, lane 9).
//!
//! MEASURED FACT (today, RTX 5090): the GPU megakernel is 1.7–6× SLOWER than
//! SIMD at every size for keyhog's detector set. So the production autoroute
//! path (`crates/cli/.../dispatch/backend.rs::measure_fastest_correct_backend`)
//! refuses to even *probe* the GPU unless `--autoroute-gpu` is set for
//! calibration —
//! `--backend gpu` still forces it for parity/research, but auto-routing never
//! picks it on its own.
//!
//! That production gate is a private function, so the operator-visible end of
//! it is pinned through the binary in `crates/cli/tests/e2e_gpu_autoroute_optin.rs`.
//! This suite pins the *decision inputs* it consults — the pure, host-
//! independent functions that decide whether a GPU *could* engage at all — so a
//! refactor of the thresholds or the gpu_could_engage predicate that would
//! silently re-open the GPU to auto-routing flips a named case here.
//!
//! Distinct from `routing_matrix.rs`: that file pins `select_backend`'s full
//! cell table (which has NO opt-in gate — it predates the measured-slowdown
//! finding). This file pins the specific predicate the *opt-in* gate stands on
//! and the exact RTX-5090 boundary the fleet runs at, so the two contracts
//! can't drift apart unnoticed.
//!
//! Every cell is an EXACT value (Law 6). No GPU hardware required: these are
//! `HardwareCaps` + pure-fn assertions, no device, no scan.

use keyhog_scanner::hw_probe::testing::{
    classify_gpu_tier, gpu_could_engage, gpu_min_bytes_for_tier, gpu_pattern_breakeven_for_tier,
    gpu_solo_bytes_for_tier, GpuTier, HardwareCaps,
};

const MIB: u64 = 1024 * 1024;

/// The actual fleet host (CLAUDE.md Law 8: RTX 5090 present). High tier.
fn rtx_5090_caps() -> HardwareCaps {
    HardwareCaps {
        physical_cores: 16,
        logical_cores: 32,
        has_avx2: true,
        has_avx512: true,
        has_neon: false,
        gpu_available: true,
        gpu_name: Some("NVIDIA GeForce RTX 5090".into()),
        gpu_vram_mb: Some(32 * 1024),
        gpu_runtime_identity: Some("test-runtime:NVIDIA GeForce RTX 5090".to_string()),
        gpu_is_software: false,
        total_memory_mb: Some(128 * 1024),
        io_uring_available: true,
        hyperscan_available: true,
    }
}

#[test]
fn rtx_5090_classifies_as_high_tier() {
    // The whole opt-in calculus depends on the 5090 being High tier (2 MiB GPU
    // floor). A misclassification to Mid/Low would silently change the
    // measured-slowdown contract's anchor point.
    assert_eq!(
        classify_gpu_tier(Some("NVIDIA GeForce RTX 5090")),
        GpuTier::High,
        "RTX 5090 must classify as High tier"
    );
}

#[test]
fn gpu_could_engage_is_true_at_the_high_tier_floor_so_the_optin_gate_is_load_bearing() {
    // This is the crux: at the high-tier floor (2 MiB, >=100 patterns) the
    // GPU COULD engage by the pure predicate. keyhog ships ~900 detectors, far
    // past the 100-pattern break-even. So WITHOUT the production opt-in gate,
    // auto-routing WOULD send a 2 MiB batch to the (measured-slower) GPU.
    // This asserts the predicate is true here, which is exactly why the
    // --autoroute-gpu gate must exist and be respected.
    let caps = rtx_5090_caps();
    let floor = gpu_min_bytes_for_tier(GpuTier::High);
    let pattern_floor = gpu_pattern_breakeven_for_tier(GpuTier::High);
    assert_eq!(floor, 2 * MIB, "high-tier GPU byte floor is 2 MiB");
    assert_eq!(
        pattern_floor, 100,
        "high-tier GPU pattern break-even is 100"
    );

    assert!(
        gpu_could_engage(&caps, floor, pattern_floor),
        "at the 2 MiB / 100-pattern high-tier floor, gpu_could_engage MUST be \
         true — this is the case the --autoroute-gpu gate exists to veto"
    );
    // keyhog's real detector count (>800) trivially clears the pattern floor.
    assert!(
        gpu_could_engage(&caps, 2 * MIB, 900),
        "with keyhog's ~900 detectors at 2 MiB, gpu_could_engage is true"
    );
}

#[test]
fn gpu_could_engage_is_false_below_the_high_tier_floor() {
    let caps = rtx_5090_caps();
    // Just under 2 MiB with the full detector set: below the byte floor and
    // below the solo cap, so the predicate is false — the swarm-of-small-files
    // common case never even reaches the opt-in gate.
    assert!(
        !gpu_could_engage(&caps, 2 * MIB - 1, 900),
        "1 byte under the 2 MiB floor with 900 patterns must NOT engage the GPU"
    );
    assert!(
        !gpu_could_engage(&caps, 64 * 1024, 900),
        "a 64 KiB batch (typical coalesced source file) must NOT engage the GPU"
    );
}

#[test]
fn gpu_could_engage_solo_path_fires_for_one_huge_file() {
    let caps = rtx_5090_caps();
    let solo = gpu_solo_bytes_for_tier(GpuTier::High);
    assert_eq!(solo, 16 * MIB, "high-tier solo break-even is 16 MiB");
    // A single 16 MiB file clears the solo cap even with ZERO pattern-count
    // benefit — the solo branch of the predicate.
    assert!(
        gpu_could_engage(&caps, solo, 0),
        "a 16 MiB single file clears the high-tier solo cap regardless of \
         pattern count"
    );
    assert!(
        !gpu_could_engage(&caps, solo - 1, 0),
        "1 byte under the solo cap with no pattern benefit must NOT engage"
    );
}

#[test]
fn software_gpu_never_engages_regardless_of_size() {
    // A software renderer (llvmpipe/lavapipe) is always slower than CPU; the
    // predicate must reject it even past every threshold, so the opt-in gate
    // never wastes an upload on it.
    let mut caps = rtx_5090_caps();
    caps.gpu_name = Some("llvmpipe (LLVM 15.0.7, 256 bits)".into());
    caps.gpu_is_software = true;
    assert!(
        !gpu_could_engage(&caps, 256 * MIB, 900),
        "a software GPU must never engage, even at 256 MiB / 900 patterns"
    );
}

#[test]
fn no_gpu_caps_never_engage() {
    let mut caps = rtx_5090_caps();
    caps.gpu_available = false;
    caps.gpu_name = None;
    assert!(
        !gpu_could_engage(&caps, 256 * MIB, 900),
        "gpu_available=false must never engage the GPU at any size"
    );
}

/// The full opt-in decision table, as the production gate composes it:
/// `autoroute_gpu && gpu_could_engage(...)`. We model the flag/config half as a
/// boolean and assert the conjunction for every (optin, bytes) cell, pinning
/// that the GPU is selected ONLY when BOTH the operator opted in AND the
/// workload could engage.
#[test]
fn optin_decision_table_gpu_only_when_optin_and_could_engage() {
    let caps = rtx_5090_caps();
    let patterns = 900;
    // (opted_in, bytes, expect_gpu_probe)
    let cells: &[(bool, u64, bool)] = &[
        (false, 64 * 1024, false), // not opted in, small  -> SIMD
        (false, 2 * MIB, false),   // not opted in, at floor -> SIMD (the gate's whole point)
        (false, 256 * MIB, false), // not opted in, huge   -> SIMD
        (true, 64 * 1024, false),  // opted in, too small  -> SIMD (could_engage false)
        (true, 2 * MIB, true),     // opted in, at floor   -> GPU probe
        (true, 256 * MIB, true),   // opted in, huge       -> GPU probe
    ];
    for &(opted_in, bytes, expect_gpu) in cells {
        let probe = opted_in && gpu_could_engage(&caps, bytes, patterns);
        assert_eq!(
            probe, expect_gpu,
            "optin={opted_in} bytes={bytes} patterns={patterns}: \
             expected gpu_probe={expect_gpu}, got {probe}"
        );
    }
}
