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
    select_backend_for_batch, select_backend_for_batch_verdict, select_backend_verdict,
    BackendRoutingReason, HardwareCaps, ScanBackend,
};
use keyhog_scanner::testing::{clear_test_backend_override, set_test_backend_override, thresholds};
use std::sync::Mutex;

static POLICY_LOCK: Mutex<()> = Mutex::new(());

fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n")
}

fn function_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("missing function signature: {signature}"));
    let tail = &src[start..];
    let open = tail
        .find('{')
        .unwrap_or_else(|| panic!("missing function body for: {signature}"));
    let mut depth = 0usize;
    for (offset, ch) in tail[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return &tail[open..=open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function body for: {signature}");
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
    // what `cpu_tier_backend` says for the same caps — no separate ladder.
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

        let batch_verdict = select_backend_for_batch_verdict(
            &caps_gpu(true, true),
            thresholds::GPU_MIN_BYTES_HIGH_TIER,
            5_000,
            1024,
        );
        assert_eq!(batch_verdict.backend, ScanBackend::SimdCpu);
        assert_eq!(
            batch_verdict.reason,
            BackendRoutingReason::GpuBatchNotDominant
        );
        assert!(batch_verdict.reason_detail().contains("do not dominate"));
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
        assert_eq!(verdict.backend, ScanBackend::Gpu);
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
            ScanBackend::Gpu
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
fn batch_dominance_guard_keeps_small_file_swarm_on_cpu() {
    with_policy(GpuRuntimePolicy::Auto, None, || {
        let gpu = caps_gpu(true, true);
        // A batch whose bytes sum past the floor but whose LARGE-chunk bytes are
        // a small minority (tiny-file swarm) must NOT route to GPU, even though
        // the size-only `select_backend` would. This is the dominance guard that
        // distinguishes the two batch shapes.
        let total = thresholds::GPU_MIN_BYTES_HIGH_TIER;
        let small_large = 1024 * 1024; // 1 MiB of large-chunk bytes out of the batch.
        assert_eq!(
            select_backend_for_batch(&gpu, total, 5_000, small_large),
            ScanBackend::SimdCpu,
            "small-file swarm (large bytes < half) must stay on SimdCpu"
        );
        // The same batch DOMINATED by large-file bytes does take the GPU.
        assert_eq!(
            select_backend_for_batch(&gpu, total, 5_000, total),
            ScanBackend::Gpu,
            "large-file-dominated batch must route to GPU"
        );
    });
}

#[test]
fn workload_selector_is_the_single_branch_owner() {
    let select_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/hw_probe/select.rs");
    let select_code =
        strip_line_comments(&std::fs::read_to_string(select_path).expect("read select.rs"));

    assert_eq!(
        select_code
            .matches("fn select_backend_for_workload(")
            .count(),
        1,
        "backend routing must have exactly one workload-policy owner"
    );

    let owner = function_body(&select_code, "fn select_backend_for_workload(");
    for required in [
        "test_backend_override()",
        "crate::gpu::gpu_disabled_by_policy()",
        "gpu_could_engage(",
        "cpu_tier_backend(caps)",
    ] {
        assert!(
            owner.contains(required),
            "the single workload selector must own `{required}`"
        );
    }

    for (signature, expected_delegate, name) in [
        (
            "pub fn select_backend(",
            "select_backend_verdict(",
            "public file/workload wrapper",
        ),
        (
            "pub fn select_backend_verdict(",
            "select_backend_for_workload(",
            "public file/workload verdict wrapper",
        ),
        (
            "pub(crate) fn select_backend_for_batch(",
            "select_backend_for_batch_verdict(",
            "batch workload wrapper",
        ),
        (
            "pub(crate) fn select_backend_for_batch_verdict(",
            "select_backend_for_workload(",
            "batch workload verdict wrapper",
        ),
    ] {
        let body = function_body(&select_code, signature);
        assert!(
            body.contains(expected_delegate),
            "{name} must delegate via `{expected_delegate}`"
        );
        for forbidden in [
            "test_backend_override()",
            "crate::gpu::gpu_disabled_by_policy()",
            "gpu_could_engage(",
            "cpu_tier_backend(caps)",
        ] {
            assert!(
                !body.contains(forbidden),
                "{name} must not carry duplicate routing branch logic: `{forbidden}`"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 3. The public Rust compatibility variant remains the SAME live engine as
//    `gpu`; retired operator spellings stay rejected by parse_backend_str.
// ---------------------------------------------------------------------------

#[test]
fn programmatic_megascan_variant_collapses_while_operator_aliases_stay_rejected() {
    for alias in [
        "mega-scan",
        "megascan",
        "gpu-mega-scan",
        "regex-nfa",
        "rule-pipeline",
    ] {
        assert_eq!(parse_backend_str(alias), None, "retired alias {alias}");
    }
    // The compatibility variant's diagnostic label remains stable for library
    // callers and persisted-data migration; it is not a CLI value.
    assert_eq!(ScanBackend::MegaScan.label(), "gpu-mega-scan");
    assert_eq!(ScanBackend::Gpu.label(), "gpu-region-presence");

    // The collapse contract: a forced MegaScan and a forced Gpu both take the
    // GPU region-presence route. `backend_dispatch.rs` keys the on-GPU path off
    // `matches!(backend, Gpu | MegaScan)`; pin that both are GPU-class and the
    // CPU arms are not, so no caller can treat MegaScan as a third engine.
    fn is_gpu_class(b: ScanBackend) -> bool {
        matches!(b, ScanBackend::Gpu | ScanBackend::MegaScan)
    }
    assert!(is_gpu_class(ScanBackend::Gpu));
    assert!(is_gpu_class(ScanBackend::MegaScan));
    assert!(!is_gpu_class(ScanBackend::SimdCpu));
    assert!(!is_gpu_class(ScanBackend::CpuFallback));
}

// ---------------------------------------------------------------------------
// 4. No dead path resurrected (source-shape guard, supporting check).
//    Goes RED if a future change re-adds one of the removed parallel GPU
//    pipelines or the duplicated CPU-tier ladder.
// ---------------------------------------------------------------------------

#[test]
fn removed_dead_gpu_pipelines_stay_removed() {
    let engine = concat!(env!("CARGO_MANIFEST_DIR"), "/src/engine/");
    // Read every engine source file once.
    let mut all = String::new();
    for entry in std::fs::read_dir(engine).expect("read engine dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            all.push_str(&std::fs::read_to_string(&path).expect("read engine source"));
        }
    }
    let code = strip_line_comments(&all);

    // The dead `ac_gpu_program` AC `vyre::Program` builder must not return.
    // (Doc-comment mentions in gpu_lazy.rs/gpu_input_budget.rs are prose, not a
    //  method def or field, so match the *executable* forms.)
    assert!(
        !code.contains("fn ac_gpu_program"),
        "ac_gpu_program method was removed as a dead route; do not re-add it — \
         region-presence is the single on-GPU trigger producer"
    );
    assert!(
        !code.contains("ac_gpu_program:"),
        "the ac_gpu_program field was removed; do not re-add it to CompiledScanner"
    );
    assert!(
        !code.contains("build_ac_bounded_ranges_program_bound_atomic"),
        "the dead AC bounded-ranges Program builder must stay removed"
    );

    // The dead per-scanner `rule_pipeline()` lazy NFA engine + field stay gone.
    // The cached wrapper `rule_pipeline_cached` and its diagnostic builder were
    // deleted as dead routes, so match the method/field/wrapper forms.
    assert!(
        !code.contains("fn rule_pipeline(&self)"),
        "the rule_pipeline() lazy method was removed (its scan was never invoked); \
         MegaScan now collapses onto region-presence"
    );
    assert!(
        !code.contains("rule_pipeline: OnceLock"),
        "the rule_pipeline OnceLock field was removed from CompiledScanner"
    );
    // The dead `rule_pipeline_cached` on-disk cache wrapper (persistence for a
    // pipeline no scan path builds) stays removed. Its private cache helpers go
    // too.
    assert!(
        !code.contains("fn rule_pipeline_cached"),
        "rule_pipeline_cached was deleted as dead public surface (zero non-test \
         callers); the live GpuLiteralSet path caches via gpu_cache, and MegaScan \
         collapses onto region-presence — do not re-add the dead pipeline cache"
    );
    assert!(
        !code.contains("fn pipeline_cache_key") && !code.contains("PIPELINE_CACHE_VERSION"),
        "the private rule-pipeline cache key helper + version const were removed \
         with rule_pipeline_cached; do not re-add a cache for an unbuilt pipeline"
    );
    assert!(
        !code.contains("fn build_rule_pipeline")
            && !code.contains("AC_GPU_MAX_MATCHES_PER_DISPATCH")
            && !code.contains("GPU_BATCH_INPUT_LIMIT:"),
        "the test-only rule-pipeline diagnostic builder and fixed-size aliases \
         were removed; keep only gpu_batch_input_limit() as the live sizing contract"
    );
    let lib_rs = strip_line_comments(
        &std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
        )
        .expect("read scanner lib.rs"),
    );
    assert!(
        !lib_rs.contains("build_rule_pipeline")
            && !lib_rs.contains("AC_GPU_MAX_MATCHES_PER_DISPATCH")
            && !lib_rs.contains("GPU_BATCH_INPUT_LIMIT:"),
        "the testing facade must not re-export the dead rule-pipeline builder or aliases"
    );

    // The megascan-specific degrade warner (warned about a degrade that can no
    // longer happen) stays removed.
    assert!(
        !code.contains("fn deny_silent_megascan_degrade"),
        "deny_silent_megascan_degrade was removed; the MegaScan->literal-set \
         degrade path no longer exists"
    );
}

#[test]
fn parse_backend_str_is_the_single_string_source() {
    // Canonical names.
    assert_eq!(parse_backend_str("gpu"), Some(ScanBackend::Gpu));
    assert_eq!(parse_backend_str("simd"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("cpu"), Some(ScanBackend::CpuFallback));
    // Case-insensitive + whitespace-trimmed.
    assert_eq!(parse_backend_str("  GPU  "), Some(ScanBackend::Gpu));
    assert_eq!(parse_backend_str("SimD"), Some(ScanBackend::SimdCpu));
    // Stable persisted-evidence label.
    assert_eq!(
        parse_backend_str("gpu-region-presence"),
        Some(ScanBackend::Gpu)
    );
    // Retired implementation labels do not silently remap.
    assert_eq!(parse_backend_str("gpu-zero-copy"), None);
    assert_eq!(parse_backend_str("literal-set"), None);
    // Unknown -> None (caller falls through to auto-routing).
    assert_eq!(parse_backend_str("quantum"), None);
    assert_eq!(parse_backend_str(""), None);
}
