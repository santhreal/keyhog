//! GPU opt-in and heuristic routing contract: the pure-fn decision inputs that
//! non-calibrating router/reporting paths use (TESTING vector 12, lane 9).
//!
//! MEASURED FACT (2026-06-20, RTX 5090): the live region-presence GPU route
//! beats Hyperscan at 8 MiB by 4.5x (ratio 0.22) after the split-positioned-matcher
//! fix. High-tier heuristic routing now engages at 8 MiB. Install-time autoroute
//! calibration is authoritative and still measures GPU candidates when explicitly
//! opted in. `--backend gpu` still forces it for parity/research.
//!
//! The calibration owner is pinned in `crates/cli/tests/unit/orchestrator/`.
//! This suite pins the heuristic threshold predicate separately so backend
//! reporting and non-calibrating library selection cannot silently change.
//!
//! Distinct from `routing_matrix.rs`: that file pins `select_backend`'s full
//! cell table. This file pins the exact RTX-5090 threshold predicate values the
//! reporting/cold-path heuristic exposes.
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
    // A misclassification to Mid/Low would silently change the measured-safe
    // high-tier heuristic anchor point.
    assert_eq!(
        classify_gpu_tier(Some("NVIDIA GeForce RTX 5090")),
        GpuTier::High,
        "RTX 5090 must classify as High tier"
    );
}

#[test]
fn gpu_could_engage_is_true_at_the_high_tier_floor_for_heuristic_routing() {
    // At the high-tier floor (8 MiB, >=100 patterns) the deterministic
    // heuristic says GPU could engage. Calibration must still measure and
    // compare candidates before any default auto scan can trust that route.
    let caps = rtx_5090_caps();
    let floor = gpu_min_bytes_for_tier(GpuTier::High);
    let pattern_floor = gpu_pattern_breakeven_for_tier(GpuTier::High);
    assert_eq!(floor, 8 * MIB, "high-tier GPU byte floor is 8 MiB");
    assert_eq!(
        pattern_floor, 100,
        "high-tier GPU pattern break-even is 100"
    );

    assert!(
        gpu_could_engage(&caps, floor, pattern_floor),
        "at the 8 MiB / 100-pattern high-tier floor, gpu_could_engage must stay \
         true for the heuristic router/reporting surface"
    );
    // keyhog's real detector count (>800) trivially clears the pattern floor.
    assert!(
        gpu_could_engage(&caps, floor, 900),
        "with keyhog's ~900 detectors at the floor, gpu_could_engage is true"
    );
}

#[test]
fn gpu_could_engage_is_false_below_the_high_tier_floor() {
    let caps = rtx_5090_caps();
    // Just under 8 MiB with the full detector set: below the byte floor and
    // below the solo cap, so the heuristic predicate is false.
    let floor = gpu_min_bytes_for_tier(GpuTier::High);
    assert!(
        !gpu_could_engage(&caps, floor - 1, 900),
        "1 byte under the high-tier floor with 900 patterns must NOT engage the GPU"
    );
    assert!(
        !gpu_could_engage(&caps, 4 * MIB, 900),
        "a 4 MiB batch must NOT engage the fixed heuristic GPU route without calibration evidence"
    );
}

#[test]
fn gpu_could_engage_solo_path_fires_for_one_huge_file() {
    let caps = rtx_5090_caps();
    let solo = gpu_solo_bytes_for_tier(GpuTier::High);
    assert_eq!(solo, 8 * MIB, "high-tier solo break-even is 8 MiB");
    // A single 8 MiB file clears the solo cap even with ZERO pattern-count
    // benefit — the solo branch of the predicate.
    assert!(
        gpu_could_engage(&caps, solo, 0),
        "an 8 MiB single file clears the high-tier solo cap regardless of \
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
    // predicate must reject it even past every threshold.
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

#[test]
fn calibration_gpu_optin_is_not_modeled_by_the_heuristic_threshold_predicate() {
    let caps = rtx_5090_caps();
    assert!(
        !gpu_could_engage(&caps, 64 * 1024, 900),
        "64 KiB remains below the heuristic GPU floor"
    );
    assert!(
        !gpu_could_engage(&caps, 4 * MIB, 900),
        "4 MiB remains below the measured-safe heuristic GPU floor"
    );
    assert!(
        gpu_could_engage(&caps, 8 * MIB, 900),
        "8 MiB is at the heuristic GPU floor"
    );
}
