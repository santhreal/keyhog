//! Regression: the PURE backend-autoroute decision.
//!
//! The live CLI dispatcher (`MeasuredBackendRouter` in
//! `crates/cli/src/orchestrator/dispatch/backend.rs`) benchmarks candidates and
//! applies a measured CI-overlap tie-break, but underneath it every side-effect-
//! free routing decision funnels through two pure predicates owned by the
//! scanner: [`gpu_could_engage`] (can a GPU EVER win for this workload+hardware)
//! and the CPU-tier ladder inside [`select_backend`] (`SimdCpu` when Hyperscan
//! is live, else `CpuFallback`). Those are host-env-independent, so we pin their
//! EXACT verdicts here. We deliberately do NOT assert the host-dependent GPU
//! branch of `select_backend`/`select_backend_verdict` (it consults the runtime
//! GPU policy + probe), only the pure predicate and the GPU-absent ladder whose
//! backend is deterministic regardless of policy env.
//!
//! Threshold source of truth: `hw_probe::thresholds` via the tier lookups.
//!   high  (RTX 40/50, A100/H100, M-Max): min=128 MiB solo=256 MiB floor=100
//!   mid   (RTX 20/30, GTX 16, Arc, M-Pro): min=256 MiB solo=512 MiB floor=500
//!   low   (iGPU / unknown):                min=512 MiB solo=1024 MiB floor=2000

use keyhog_scanner::hw_probe::{
    gpu_could_engage, gpu_routing_profile, gpu_routing_profiles, parse_backend_str, select_backend,
    select_backend_verdict, BackendRoutingReason, HardwareCaps, ScanBackend,
};

/// Single owner of the binary-megabyte multiplier (mirrors
/// `hw_probe::thresholds::MIB`) so the expected byte constants below read the
/// same way the production thresholds are declared.
const MIB: u64 = 1024 * 1024;

/// Build a `HardwareCaps` with the routing-relevant knobs set and everything
/// else fixed to inert, decision-irrelevant defaults.
fn caps(
    gpu_available: bool,
    gpu_name: Option<&str>,
    gpu_is_software: bool,
    hyperscan_available: bool,
) -> HardwareCaps {
    HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: true,
        has_avx512: false,
        has_neon: false,
        gpu_available,
        gpu_name: gpu_name.map(str::to_string),
        gpu_vram_mb: gpu_name.map(|_| 24_576),
        gpu_runtime_identity: None,
        gpu_is_software,
        total_memory_mb: Some(32_768),
        io_uring_available: false,
        hyperscan_available,
    }
}

// ─── gpu_could_engage: pure predicate, exact boundaries ──────────────────────

#[test]
fn tiny_input_high_tier_gpu_cannot_engage() {
    // A 1 KiB file on the fastest tier: below both the 128 MiB min floor and the
    // 256 MiB solo cap, and pattern count is irrelevant when neither byte gate is
    // met. Lowest-overhead backend wins -> GPU is excluded.
    let hw = caps(true, Some("NVIDIA GeForce RTX 4090"), false, true);
    assert!(!gpu_could_engage(&hw, 1024, 10));
    assert!(!gpu_could_engage(&hw, 0, 1_000_000));
}

#[test]
fn high_tier_min_bytes_pattern_floor_boundary() {
    // High tier: min=128 MiB, floor=100 patterns, solo=256 MiB.
    let hw = caps(true, Some("NVIDIA GeForce RTX 5090"), false, true);
    let min = 128 * MIB;
    // At the minimum: the pattern-count gate remains load-bearing.
    assert!(gpu_could_engage(&hw, min, 100));
    assert!(!gpu_could_engage(&hw, min, 99));
    assert!(!gpu_could_engage(&hw, min, 0));
    // One byte below the min floor with a huge pattern count -> still no (the
    // AND gate needs BOTH min+patterns, and solo is not met either).
    assert!(!gpu_could_engage(&hw, min - 1, 1_000_000));
}

#[test]
fn high_tier_solo_cap_overrides_pattern_count() {
    // At/above the 256 MiB solo cap a single very large file engages GPU with
    // ZERO patterns; one byte below it needs the pattern path (which 1 pattern
    // fails) so it stays on CPU/SIMD.
    let hw = caps(true, Some("NVIDIA RTX 4090"), false, true);
    let solo = 256 * MIB;
    assert!(gpu_could_engage(&hw, solo, 0));
    assert!(gpu_could_engage(&hw, solo + 1, 0));
    assert!(!gpu_could_engage(&hw, solo - 1, 1));
}

#[test]
fn mid_tier_thresholds_exact() {
    // Mid tier: min=256 MiB, floor=500, solo=512 MiB.
    let hw = caps(true, Some("NVIDIA GeForce RTX 3080"), false, true);
    assert!(gpu_could_engage(&hw, 256 * MIB, 500));
    assert!(!gpu_could_engage(&hw, 256 * MIB, 499));
    // Solo cap engages with no patterns.
    assert!(gpu_could_engage(&hw, 512 * MIB, 0));
    // High-tier's 100-pattern floor must NOT apply here: 256 MiB + 100 patterns
    // is below the mid floor of 500, so it stays off GPU.
    assert!(!gpu_could_engage(&hw, 256 * MIB, 100));
}

#[test]
fn low_tier_unknown_adapter_thresholds_exact() {
    // Unknown adapter name AND missing name both classify Low:
    // min=512 MiB, floor=2000, solo=1024 MiB.
    let named = caps(true, Some("Intel UHD Graphics 620"), false, true);
    let unnamed = caps(true, None, false, true);
    for hw in [&named, &unnamed] {
        assert!(gpu_could_engage(hw, 512 * MIB, 2000));
        assert!(!gpu_could_engage(hw, 512 * MIB, 1999));
        assert!(gpu_could_engage(hw, 1024 * MIB, 0));
        // Mid-tier's 256 MiB floor must not leak down to Low.
        assert!(!gpu_could_engage(hw, 256 * MIB, 100_000));
    }
}

#[test]
fn software_renderer_never_engages_regardless_of_size() {
    // llvmpipe/lavapipe are always slower than CPU: even a 4 GiB buffer with a
    // huge pattern count stays off GPU.
    let hw = caps(true, Some("llvmpipe (LLVM 15.0.7, 256 bits)"), true, true);
    assert!(!gpu_could_engage(&hw, 4 * 1024 * MIB, 1_000_000));
    assert!(!gpu_could_engage(&hw, 256 * MIB, 500));
}

#[test]
fn no_gpu_probe_never_engages() {
    // gpu_available == false short-circuits to false before any tier lookup.
    let hw = caps(false, None, false, true);
    assert!(!gpu_could_engage(&hw, 8 * 1024 * MIB, 10_000_000));
}

// ─── tier profile table: exact threshold values ─────────────────────────────

#[test]
fn routing_profile_high_tier_exact_values() {
    let p = gpu_routing_profile(Some("NVIDIA GeForce RTX 4090"));
    assert_eq!(p.tier, "high");
    assert_eq!(p.min_bytes, 128 * MIB);
    assert_eq!(p.solo_bytes, 256 * MIB);
    assert_eq!(p.pattern_breakeven, 100);
}

#[test]
fn routing_profile_mid_and_low_exact_values() {
    let mid = gpu_routing_profile(Some("NVIDIA GeForce RTX 3070"));
    assert_eq!(mid.tier, "mid");
    assert_eq!(mid.min_bytes, 256 * MIB);
    assert_eq!(mid.solo_bytes, 512 * MIB);
    assert_eq!(mid.pattern_breakeven, 500);

    let low = gpu_routing_profile(None);
    assert_eq!(low.tier, "low");
    assert_eq!(low.min_bytes, 512 * MIB);
    assert_eq!(low.solo_bytes, 1024 * MIB);
    assert_eq!(low.pattern_breakeven, 2000);
}

#[test]
fn routing_profiles_table_order_and_length() {
    let table = gpu_routing_profiles();
    assert_eq!(table.len(), 3);
    // Fixed order: High, Mid, Low.
    assert_eq!(table[0].tier, "high");
    assert_eq!(table[1].tier, "mid");
    assert_eq!(table[2].tier, "low");
    // The table entries agree byte-for-byte with the per-adapter lookup.
    assert_eq!(table[0].min_bytes, 128 * MIB);
    assert_eq!(table[1].solo_bytes, 512 * MIB);
    assert_eq!(table[2].pattern_breakeven, 2000);
}

// ─── string parsing: canonical backend aliases ──────────────────────────────

#[test]
fn parse_backend_str_maps_canonical_aliases() {
    assert_eq!(parse_backend_str("gpu"), Some(ScanBackend::Gpu));
    assert_eq!(
        parse_backend_str("gpu-region-presence"),
        Some(ScanBackend::Gpu)
    );
    assert_eq!(parse_backend_str("simd"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("cpu"), Some(ScanBackend::CpuFallback));
    assert_eq!(parse_backend_str("simd-regex"), Some(ScanBackend::SimdCpu));
    assert_eq!(
        parse_backend_str("cpu-fallback"),
        Some(ScanBackend::CpuFallback)
    );
}

#[test]
fn parse_backend_str_trims_lowercases_and_rejects_unknown() {
    // Case-insensitive + surrounding whitespace tolerated.
    assert_eq!(parse_backend_str("  GPU  "), Some(ScanBackend::Gpu));
    assert_eq!(parse_backend_str("SIMD-Regex"), Some(ScanBackend::SimdCpu));
    // Genuinely unknown strings are rejected (None), never silently routed.
    assert_eq!(parse_backend_str("quantum"), None);
    assert_eq!(parse_backend_str(""), None);
    assert_eq!(parse_backend_str("gpu2"), None);
    assert_eq!(parse_backend_str("mega-scan"), None);
    assert_eq!(parse_backend_str("literal-set"), None);
    assert_eq!(parse_backend_str("hyperscan"), None);
    assert_eq!(parse_backend_str("scalar"), None);
}

// ─── stable operator-facing labels ──────────────────────────────────────────

#[test]
fn scan_backend_labels_are_stable() {
    assert_eq!(ScanBackend::Gpu.label(), "gpu-region-presence");
    assert_eq!(ScanBackend::SimdCpu.label(), "simd-regex");
    assert_eq!(ScanBackend::CpuFallback.label(), "cpu-fallback");
}

#[test]
fn backend_routing_reason_labels_are_stable() {
    assert_eq!(BackendRoutingReason::TestOverride.label(), "test_override");
    assert_eq!(
        BackendRoutingReason::GpuDisabledByPolicy.label(),
        "gpu_disabled_by_policy"
    );
    assert_eq!(BackendRoutingReason::GpuProbeMiss.label(), "gpu_probe_miss");
    assert_eq!(
        BackendRoutingReason::GpuSoftwareRenderer.label(),
        "gpu_software_renderer"
    );
    assert_eq!(
        BackendRoutingReason::GpuBatchNotDominant.label(),
        "gpu_batch_not_dominant"
    );
    assert_eq!(
        BackendRoutingReason::GpuThresholdNotMet.label(),
        "gpu_threshold_not_met"
    );
    assert_eq!(BackendRoutingReason::GpuSelected.label(), "gpu_selected");
}

// ─── CPU-tier ladder: deterministic when no GPU is in play ──────────────────

#[test]
fn no_gpu_cpu_tier_ladder_simd_beats_fallback() {
    // With no GPU adapter the routing decision is purely the CPU ladder and is
    // independent of the runtime GPU policy env: Hyperscan live -> SimdCpu,
    // otherwise the always-present scalar CpuFallback. This pins the
    // `SimdCpu < CpuFallback` preference (SimdCpu chosen whenever available).
    let with_hs = caps(false, None, false, true);
    let without_hs = caps(false, None, false, false);
    assert_eq!(select_backend(&with_hs, 1024, 5), ScanBackend::SimdCpu);
    assert_eq!(
        select_backend(&without_hs, 1024, 5),
        ScanBackend::CpuFallback
    );
    // The size/pattern axis cannot flip a GPU-absent host onto GPU.
    assert_eq!(
        select_backend(&with_hs, 8 * 1024 * MIB, 1_000_000),
        ScanBackend::SimdCpu
    );
}

#[test]
fn no_gpu_verdict_reports_workload_and_low_tier_profile() {
    // The verdict struct echoes the exact workload inputs and, for an
    // unclassified (no-name) adapter, the low-tier threshold profile. Backend is
    // deterministic here (GPU absent -> CPU ladder), so we assert it; the reason
    // is host-policy dependent and intentionally left unasserted.
    let hw = caps(false, None, false, true);
    let v = select_backend_verdict(&hw, 4096, 42);
    assert_eq!(v.backend, ScanBackend::SimdCpu);
    assert_eq!(v.workload_bytes, 4096);
    assert_eq!(v.pattern_count, 42);
    assert_eq!(v.gpu_tier, "low");
    assert_eq!(v.gpu_min_bytes, 512 * MIB);
    assert_eq!(v.gpu_solo_bytes, 1024 * MIB);
    assert_eq!(v.gpu_pattern_breakeven, 2000);
    assert_eq!(v.gpu_available, false);
}
