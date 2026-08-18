//! LANE 2 (ARCHITECTURE / DEDUP / INSUFFICIENCY) regression pins.
//!
//! Locks the collapsed single-backend model after the dead parallel GPU paths
//! were removed (the `RulePipeline` "MegaScan" regex-NFA engine, the
//! `ac_gpu_program` AC `vyre::Program` builder, and the duplicated CPU-tier
//! ladders). Each test goes RED if a future change resurrects a dead route,
//! re-duplicates the CPU-tier decision, or lets a routing cell drift.
//!
//! Pure-logic over `HardwareCaps` + the hw_probe routers: no GPU hardware and
//! no real scan. GPU runtime policy is process-global and explicit backend pins
//! use the scanner testing facade, so every mutable cell serializes on
//! [`POLICY_LOCK`].

use keyhog_scanner::gpu::{gpu_runtime_policy, set_gpu_runtime_policy, GpuRuntimePolicy};
use keyhog_scanner::hw_probe::testing::{
    cpu_tier_backend, gpu_could_engage, parse_backend_str, select_backend,
    select_backend_for_batch, select_backend_verdict,
    BackendRoutingReason, HardwareCaps, ScanBackend,
};
use keyhog_scanner::testing::{clear_test_backend_override, set_test_backend_override, thresholds};
use std::sync::Mutex;

static POLICY_LOCK: Mutex<()> = Mutex::new(());
const fn automatic_gpu_backend() -> ScanBackend {
    if cfg!(target_os = "macos") {
        ScanBackend::GpuMetal
    } else {
        ScanBackend::GpuWgpu
    }
}

/// High-tier discrete-GPU caps (RTX 5090 class). `hyperscan`/`simd` toggle the
/// CPU tier.
fn caps_gpu(hyperscan: bool, simd: bool) -> HardwareCaps {
    HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: simd,
        has_avx512: false,
        has_neon: false,
        gpu_available: true,
        gpu_name: Some("NVIDIA GeForce RTX 5090".into()),
        gpu_vram_mb: Some(24 * 1024),
        gpu_runtime_identity: Some("test-runtime:NVIDIA GeForce RTX 5090".to_string()),
        gpu_is_software: false,
        total_memory_mb: Some(64 * 1024),
        io_uring_available: true,
        hyperscan_available: hyperscan,
        hyperscan_runtime_identity: None,
    }
}

fn caps_no_gpu(hyperscan: bool, simd: bool) -> HardwareCaps {
    HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: simd,
        has_avx512: false,
        has_neon: false,
        gpu_available: false,
        gpu_name: None,
        gpu_vram_mb: None,
        gpu_runtime_identity: None,
        gpu_is_software: false,
        total_memory_mb: Some(64 * 1024),
        io_uring_available: true,
        hyperscan_available: hyperscan,
        hyperscan_runtime_identity: None,
    }
}

/// Run `body` with an explicit GPU runtime policy and an optional race-free
/// backend test override, restoring state on exit.
fn with_policy<R>(policy: GpuRuntimePolicy, backend: Option<&str>, body: impl FnOnce() -> R) -> R {
    let _g = POLICY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior_policy = gpu_runtime_policy();
    set_gpu_runtime_policy(policy);
    if let Some(backend) = backend {
        set_test_backend_override(parse_backend_str(backend));
    } else {
        clear_test_backend_override();
    }
    let out = body();
    set_gpu_runtime_policy(prior_policy);
    clear_test_backend_override();
    out
}

const SIXTEEN_MIB: u64 = 16 * 1024 * 1024;
const REQUIRED_EIGHT_MIB: u64 = 8 * 1024 * 1024;

// ---------------------------------------------------------------------------
// 1. `cpu_tier_backend`: the ONE CPU-tier source of truth (DEDUP).
// ---------------------------------------------------------------------------

#[test]
fn cpu_tier_backend_is_the_single_simd_vs_scalar_source() {
    // `SimdCpu` strictly denotes the Hyperscan/Vectorscan prefilter path, so it
    // is chosen ONLY when Hyperscan is compiled in and live ("Fail closed
    // selected SIMD routes", 0eb97683a). CPU ISA flags are operator-visibility
    // only: an accelerated ISA without Hyperscan does NOT prove the simd-regex
    // backend exists, so it must resolve to the scalar `CpuFallback` rather than
    // auto-select a SimdCpu the scan path cannot honor (its `simd_prefilter`
    // would be absent and the selected-backend guard would fail closed).

    // Hyperscan compiled in -> SimdCpu, independent of ISA flags.
    assert_eq!(
        cpu_tier_backend(&caps_no_gpu(true, false)),
        ScanBackend::SimdCpu,
        "hyperscan_available must pick SimdCpu"
    );
    assert_eq!(
        cpu_tier_backend(&caps_no_gpu(true, true)),
        ScanBackend::SimdCpu,
        "hyperscan_available picks SimdCpu regardless of ISA flags"
    );
    // No Hyperscan: an accelerated ISA (AVX2 here) alone is NOT sufficient.
    assert_eq!(
        cpu_tier_backend(&caps_no_gpu(false, true)),
        ScanBackend::CpuFallback,
        "SIMD ISA without Hyperscan does not prove the simd-regex backend; must fall to CpuFallback"
    );
    // Neither hyperscan nor SIMD -> pure scalar CpuFallback.
    assert_eq!(
        cpu_tier_backend(&caps_no_gpu(false, false)),
        ScanBackend::CpuFallback,
        "no hyperscan and no SIMD must fall to the scalar CpuFallback"
    );
}

#[test]
fn select_backend_routes_cpu_tier_through_the_shared_helper() {
    // With the GPU explicitly disabled, `select_backend` must produce EXACTLY
    // what `cpu_tier_backend` says for the same caps (no separate ladder).
    with_policy(GpuRuntimePolicy::Disabled, None, || {
        for &(hs, simd) in &[(true, true), (true, false), (false, true), (false, false)] {
            let caps = caps_gpu(hs, simd); // GPU present but runtime policy disables it.
            assert_eq!(
                select_backend(&caps, SIXTEEN_MIB, 5_000),
                cpu_tier_backend(&caps),
                "select_backend under disabled GPU policy must equal cpu_tier_backend (hs={hs} simd={simd})"
            );
            assert_eq!(
                select_backend_for_batch(&caps, SIXTEEN_MIB, 5_000, SIXTEEN_MIB),
                cpu_tier_backend(&caps),
                "select_backend_for_batch under disabled GPU policy must equal cpu_tier_backend (hs={hs} simd={simd})"
            );
        }
    });
}

#[test]
fn routing_verdict_surfaces_every_cpu_reason() {
    with_policy(GpuRuntimePolicy::Disabled, None, || {
        let caps = caps_gpu(true, true);
        let verdict = select_backend_verdict(&caps, thresholds::GPU_MIN_BYTES_HIGH_TIER, 5_000);
        assert_eq!(verdict.backend, ScanBackend::SimdCpu);
        assert_eq!(verdict.reason, BackendRoutingReason::GpuDisabledByPolicy);
        assert_eq!(verdict.reason.label(), "gpu_disabled_by_policy");
        assert!(
            verdict.reason_detail().contains("runtime policy"),
            "disabled-policy verdict must explain the policy cause"
        );
    });

    with_policy(GpuRuntimePolicy::Auto, None, || {
        let no_gpu = caps_no_gpu(true, true);
        let no_gpu_verdict =
            select_backend_verdict(&no_gpu, thresholds::GPU_MIN_BYTES_HIGH_TIER, 5_000);
        assert_eq!(no_gpu_verdict.backend, ScanBackend::SimdCpu);
        assert_eq!(no_gpu_verdict.reason, BackendRoutingReason::GpuProbeMiss);
        assert!(no_gpu_verdict.reason_detail().contains("hardware probe"));

        let mut software = caps_gpu(true, true);
        software.gpu_is_software = true;
        software.gpu_name = Some("llvmpipe (LLVM 15)".into());
        let software_verdict =
            select_backend_verdict(&software, thresholds::GPU_MIN_BYTES_HIGH_TIER, 5_000);
        assert_eq!(software_verdict.backend, ScanBackend::SimdCpu);
        assert_eq!(
            software_verdict.reason,
            BackendRoutingReason::GpuSoftwareRenderer
        );
        assert!(software_verdict
            .reason_detail()
            .contains("software renderer"));

        let threshold_verdict = select_backend_verdict(&caps_gpu(true, true), 1024, 5_000);
        assert_eq!(threshold_verdict.backend, ScanBackend::SimdCpu);
        assert_eq!(
            threshold_verdict.reason,
            BackendRoutingReason::GpuThresholdNotMet
        );
        assert!(threshold_verdict
            .reason_detail()
            .contains("GPU thresholds not met"));

    });
}

#[test]
fn routing_verdict_surfaces_gpu_selection_reason() {
    with_policy(GpuRuntimePolicy::Auto, None, || {
        let verdict = select_backend_verdict(
            &caps_gpu(true, true),
            thresholds::GPU_MIN_BYTES_HIGH_TIER,
            5_000,
        );
        assert_eq!(verdict.backend, automatic_gpu_backend());
        assert_eq!(verdict.reason, BackendRoutingReason::GpuSelected);
        assert_eq!(verdict.reason.label(), "gpu_selected");
        assert_eq!(verdict.workload_bytes, thresholds::GPU_MIN_BYTES_HIGH_TIER);
        assert_eq!(verdict.pattern_count, 5_000);
        assert_eq!(verdict.gpu_tier, "high");
        assert!(verdict.reason_detail().contains("GPU thresholds met"));
    });
}

// ---------------------------------------------------------------------------
// 2. The selection matrix: exact backend per (caps, bytes, patterns, env).
// ---------------------------------------------------------------------------

#[test]
fn selection_matrix_exact_cells() {
    // Force the GPU into play (self-hosted-runner override) so the GPU branch
    // is reachable on CI, then assert each documented cell exactly.
    with_policy(GpuRuntimePolicy::Auto, None, || {
        let gpu = caps_gpu(true, true);

        // The fixed heuristic is deliberately conservative: an 8 MiB win is
        // eligible only through persisted calibration for that exact workload.
        assert!(!gpu_could_engage(&gpu, REQUIRED_EIGHT_MIB, 5_000));
        assert_eq!(
            select_backend(&gpu, REQUIRED_EIGHT_MIB, 5_000),
            ScanBackend::SimdCpu
        );
        // 16 MiB is also below the 256 MiB high-tier solo cap.
        assert!(!gpu_could_engage(&gpu, SIXTEEN_MIB, 1));
        assert_eq!(select_backend(&gpu, SIXTEEN_MIB, 1), ScanBackend::SimdCpu);

        // High-tier measured-safe min with enough patterns: GPU engages.
        assert!(gpu_could_engage(
            &gpu,
            thresholds::GPU_MIN_BYTES_HIGH_TIER,
            5_000
        ));
        assert_eq!(
            select_backend(&gpu, thresholds::GPU_MIN_BYTES_HIGH_TIER, 5_000),
            automatic_gpu_backend()
        );

        // Tiny workload below every floor: GPU cannot engage -> SimdCpu.
        assert!(!gpu_could_engage(&gpu, 4 * 1024, 1));
        assert_eq!(select_backend(&gpu, 4 * 1024, 1), ScanBackend::SimdCpu);

        // Software GPU is never used even when present.
        let mut sw = gpu.clone();
        sw.gpu_is_software = true;
        sw.gpu_name = Some("llvmpipe (LLVM 15)".into());
        assert!(!gpu_could_engage(
            &sw,
            thresholds::GPU_MIN_BYTES_HIGH_TIER,
            5_000
        ));
        assert_eq!(
            select_backend(&sw, thresholds::GPU_MIN_BYTES_HIGH_TIER, 5_000),
            ScanBackend::SimdCpu
        );

        // gpu_available=false -> CPU tier regardless of size.
        let none = caps_no_gpu(true, true);
        assert!(!gpu_could_engage(&none, 1 << 30, 100_000));
        assert_eq!(
            select_backend(&none, 1 << 30, 100_000),
            ScanBackend::SimdCpu
        );
    });
}

#[test]
fn batch_selection_delegates_to_backend_routing() {
    with_policy(GpuRuntimePolicy::Auto, None, || {
        let gpu = caps_gpu(true, true);
        let total = thresholds::GPU_MIN_BYTES_HIGH_TIER;
        assert_eq!(
            select_backend_for_batch(&gpu, total, 5_000, 1024),
            select_backend(&gpu, total, 5_000),
            "select_backend_for_batch must match select_backend"
        );
    });
}

// ---------------------------------------------------------------------------
// 3. Retired operator spellings stay rejected by parse_backend_str.
// ---------------------------------------------------------------------------

#[test]
fn retired_megascan_aliases_stay_rejected() {
    for alias in [
        "mega-scan",
        "megascan",
        "gpu-mega-scan",
        "regex-nfa",
        "rule-pipeline",
    ] {
        assert_eq!(parse_backend_str(alias), None, "retired alias {alias}");
    }
    assert_eq!(ScanBackend::GpuCuda.label(), "gpu-cuda-region-presence");
    assert_eq!(ScanBackend::GpuWgpu.label(), "gpu-wgpu-region-presence");
}

// ---------------------------------------------------------------------------
// 4. No dead path resurrected (source-shape guard, supporting check).
//    Goes RED if a future change re-adds one of the removed parallel GPU
//    pipelines or the duplicated CPU-tier ladder.
// ---------------------------------------------------------------------------

#[test]
fn parse_backend_str_is_the_single_string_source() {
    // Canonical names.
    assert_eq!(parse_backend_str("gpu"), None);
    assert_eq!(parse_backend_str("gpu-cuda"), Some(ScanBackend::GpuCuda));
    assert_eq!(parse_backend_str("gpu-wgpu"), Some(ScanBackend::GpuWgpu));
    assert_eq!(parse_backend_str("simd"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("cpu"), Some(ScanBackend::CpuFallback));
    // Case-insensitive + whitespace-trimmed.
    assert_eq!(
        parse_backend_str("  GPU-WGPU  "),
        Some(ScanBackend::GpuWgpu)
    );
    assert_eq!(parse_backend_str("SimD"), Some(ScanBackend::SimdCpu));
    // Stable persisted-evidence label.
    assert_eq!(
        parse_backend_str("gpu-cuda-region-presence"),
        Some(ScanBackend::GpuCuda)
    );
    // Retired implementation labels do not silently remap.
    assert_eq!(parse_backend_str("gpu-zero-copy"), None);
    assert_eq!(parse_backend_str("literal-set"), None);
    // Unknown -> None (caller falls through to auto-routing).
    assert_eq!(parse_backend_str("quantum"), None);
    assert_eq!(parse_backend_str(""), None);
}
