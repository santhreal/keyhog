use super::*;

#[test]
fn autoroute_host_identity_uses_dependency_owned_gpu_compile_fact() {
    let mut caps = test_hw_caps();
    caps.gpu_available = true;
    caps.gpu_name = Some("NVIDIA GeForce RTX 5090".to_string());
    caps.gpu_runtime_identity = Some("cuda:NVIDIA:RTX5090:driver-565".to_string());

    let peer = "gpu-cuda-region-presence:cuda@0.6.4:NVIDIA RTX 5090:ordinal=0:cuda:NVIDIA:RTX5090:driver-565";
    let profile = AutorouteHostProfile::from_caps(
        &caps,
        Some(peer),
        keyhog_scanner::hw_probe::gpu_backend_compiled(),
        test_eligible_backends(
            keyhog_scanner::hw_probe::gpu_backend_compiled().then_some(ScanBackend::GpuCuda),
        ),
    );
    if keyhog_scanner::hw_probe::gpu_backend_compiled() {
        assert_eq!(profile.gpu_name, caps.gpu_name);
        assert_eq!(profile.gpu_runtime_backend.as_deref(), Some(peer));
        assert_eq!(profile.gpu_driver_runtime_identity.as_deref(), Some(peer));
    } else {
        assert_eq!(profile.gpu_name, None);
        assert_eq!(profile.gpu_runtime_backend, None);
        assert_eq!(profile.gpu_driver_runtime_identity, None);
    }
}

#[test]
fn hyperscan_runtime_change_invalidates_autoroute_host_identity() {
    let original = test_host(None);
    let mut upgraded = original.clone();
    upgraded.hyperscan_runtime_identity = Some("hyperscan-test-runtime-5.4.3".to_string());

    assert_ne!(
        host_identity_digest(&original),
        host_identity_digest(&upgraded),
        "changing only the live Hyperscan/Vectorscan runtime must invalidate persisted SIMD evidence"
    );
    assert_ne!(original, upgraded);
}

#[test]
fn hyperscan_runtime_identity_must_match_backend_availability() {
    let mut missing = test_host(None);
    missing.hyperscan_runtime_identity = None;
    assert_eq!(
        missing.require_exact_identity(),
        Err("Hyperscan runtime identity is unavailable")
    );

    let mut impossible = test_host(None);
    impossible.hyperscan_available = false;
    impossible.eligible_backends = vec![ScanBackend::CpuFallback.label().to_string()];
    assert_eq!(
        impossible.require_exact_identity(),
        Err("Hyperscan runtime identity is present while the backend is unavailable")
    );
}

#[test]
fn host_profile_strips_gpu_runtime_when_no_hardware_gpu_participates() {
    let mut cpu_only = test_hw_caps();
    cpu_only.gpu_available = false;
    cpu_only.gpu_name = Some("stale probe name".to_string());
    cpu_only.gpu_runtime_identity = Some("stale runtime identity".to_string());
    cpu_only.gpu_is_software = false;
    let cpu_profile =
        AutorouteHostProfile::from_caps(&cpu_only, None, true, test_eligible_backends(None));
    assert_eq!(
        cpu_profile.gpu_name, None,
        "CPU-only autoroute identity must not persist stale GPU device names"
    );
    assert_eq!(
        cpu_profile.gpu_runtime_backend, None,
        "CPU-only autoroute identity must not inherit a compiled GPU runtime backend"
    );
    assert_eq!(
        cpu_profile.gpu_driver_runtime_identity, None,
        "CPU-only autoroute identity must not persist GPU driver identity"
    );

    let mut software_gpu = test_hw_caps();
    software_gpu.gpu_available = true;
    software_gpu.gpu_name = Some("llvmpipe (LLVM 15.0.7)".to_string());
    software_gpu.gpu_runtime_identity = Some("wgpu:Vulkan:llvmpipe:mesa".to_string());
    software_gpu.gpu_is_software = true;
    let software_profile =
        AutorouteHostProfile::from_caps(&software_gpu, None, true, test_eligible_backends(None));
    assert_eq!(
        software_profile.gpu_runtime_backend, None,
        "software renderer runtimes do not participate in autoroute calibration"
    );
    assert_eq!(
        software_profile.gpu_driver_runtime_identity, None,
        "software renderer driver churn must not invalidate CPU/SIMD autoroute decisions"
    );
    assert_eq!(
        software_profile.gpu_name.as_deref(),
        Some("llvmpipe (LLVM 15.0.7)"),
        "the software renderer device name still records host identity"
    );
    assert!(
        software_profile.gpu_is_software,
        "software renderer status remains part of host identity"
    );
}

#[test]
fn cuda_only_acquired_peer_remains_part_of_exact_host_identity() {
    let caps = test_hw_caps();
    let peer = "gpu-cuda-region-presence:cuda@0.6.4:NVIDIA RTX 5090:ordinal=0:nvidia-kernel:580.95";
    let mut profile = AutorouteHostProfile::from_caps(
        &caps,
        Some(peer),
        true,
        test_eligible_backends(Some(ScanBackend::GpuCuda)),
    );
    profile.cpu_model = Some("test-cpu".to_string());

    assert_eq!(profile.gpu_name.as_deref(), Some(peer));
    assert_eq!(profile.gpu_runtime_backend.as_deref(), Some(peer));
    assert_eq!(profile.gpu_driver_runtime_identity.as_deref(), Some(peer));
    profile
        .require_exact_identity()
        .expect("a CUDA-only acquired peer with exact identity must calibrate");
}

#[cfg(target_os = "linux")]
#[test]
fn cpuinfo_parser_prefers_model_name_over_processor_index() {
    let cpuinfo = "\
processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model name\t: Intel(R) Core(TM) Ultra 9 285K
processor\t: 1
model name\t: Intel(R) Core(TM) Ultra 9 285K
";

    assert_eq!(
        super::super::host::parse_cpuinfo_model(cpuinfo).as_deref(),
        Some("Intel(R) Core(TM) Ultra 9 285K"),
        "autoroute host identity must use the CPU model, not Linux core index 0"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn cpuinfo_parser_keeps_textual_processor_fallback() {
    let cpuinfo = "\
processor\t: ARMv7 Processor rev 5 (v7l)
BogoMIPS\t: 38.40
";

    assert_eq!(
        super::super::host::parse_cpuinfo_model(cpuinfo).as_deref(),
        Some("ARMv7 Processor rev 5 (v7l)"),
        "textual Linux Processor entries remain valid when model name/hardware are absent"
    );
}

#[test]
fn paired_same_backend_rounds_retain_shared_host_drift() {
    let candidate_trials = vec![
        10_000_000, 30_000_000, 12_000_000, 28_000_000, 14_000_000, 26_000_000, 16_000_000,
    ];
    let competitor_trials = candidate_trials
        .iter()
        .map(|trial| trial + 1_000_000)
        .collect::<Vec<_>>();
    let candidate =
        BackendTimingEvidence::from_trial_ns(candidate_trials).expect("candidate trials");
    let competitor =
        BackendTimingEvidence::from_trial_ns(competitor_trials).expect("competitor trials");
    let decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::CpuFallback,
        8 * 1024 * 1024,
        1,
        test_measurement_shape_evidence(8 * 1024 * 1024, 1),
        7,
        1,
        route_timings(
            BackendTimingEvidence::constant_ms(200, AUTOROUTE_CALIBRATION_TRIALS),
            Some(candidate),
            None,
            None,
            None,
            None,
            Some(competitor),
            None,
            None,
            None,
        ),
        false,
        false,
    );

    assert_eq!(
        decision.resolved_routing_route(),
        Some(MeasuredRoute {
            backend: ScanBackend::CpuFallback,
            phase2_plain_localizer: false,
            phase2_keyword_localizer: false,
            gpu_pipeline_depth: 1,
        }),
        "paired rounds must prove a stable plan delta even when marginal intervals share host drift"
    );
}

#[test]
fn autoroute_cache_rejects_duplicate_config_host_generations_on_load_and_inspection() {
    let dir = tempfile::TempDir::new().expect("autoroute duplicate-config tempdir");
    let path = dir.path().join("autoroute.json");
    let detector_digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let mut decisions = HashMap::new();
    decisions.insert(
        test_workload_key(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    save_autoroute_cache(
        &path,
        detector_digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect("write valid cache before tampering");

    let mut cache: AutorouteCache =
        serde_json::from_slice(&std::fs::read(&path).expect("read valid autoroute cache"))
            .expect("parse valid autoroute cache");
    cache.configs.push(cache.configs[0].clone());
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&cache).expect("serialize duplicate config cache"),
    )
    .expect("write duplicate config cache");

    let error = load_autoroute_cache(
        &path,
        detector_digest,
        test_rules_digest(),
        config_digest,
        &host,
    )
    .expect_err("duplicate config and host generations must be rejected before route selection")
    .to_string();
    assert!(
        error.contains("duplicate config and host generation"),
        "load error must identify the ambiguous generation identity: {error}"
    );
    let inspection = inspect_autoroute_cache(Some(&path));
    assert!(
        inspection
            .error
            .as_deref()
            .is_some_and(|error| error.contains("duplicate config and host generation")),
        "inspection must reject the same ambiguous cache: {inspection:?}"
    );
    assert!(inspection.configs.is_empty());
}
