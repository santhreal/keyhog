use super::*;

#[test]
fn cpu_only_calibration_cannot_replay_under_a_gpu_admitting_scan() {
    // v51 removed `calibration.excludes_gpu_candidates` from the resolved-config
    // digest, because hashing it there produced a guaranteed miss on every host
    // and build with no GPU candidate. This is the guard that keeps the
    // property the removed field was reaching for: the persisted host
    // generation carries the candidate census and the full GPU device, runtime,
    // driver and batch-limit identity, so evidence measured with GPU excluded
    // can only be found again by a scan whose host profile matches exactly.
    let dir = tempfile::tempdir().expect("gpu exclusion isolation tempdir");
    let path = dir.path().join("autoroute.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;

    let cpu_only = test_host(None);
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(key, valid_decision_for_host(&cpu_only));
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &cpu_only,
        &decisions,
    )
    .expect("CPU-only calibration persists");

    // Same binary, same corpus, same resolved config digest. Only the admitted
    // candidate set differs, which is exactly the case the config digest used
    // to carry.
    let gpu_admitting = test_host(Some("NVIDIA GeForce RTX 5090"));
    let error = load_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &gpu_admitting,
    )
    .expect_err("CPU-only route evidence must not replay under a scan that admits a GPU")
    .to_string();
    assert!(
        error.contains("host profile mismatch"),
        "refusal must name the host generation, not a config mismatch: {error}"
    );

    // And the scan that measured it still finds its own evidence, which is the
    // half the old config-digest field broke.
    assert_eq!(
        load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &cpu_only,)
            .expect("CPU-only evidence replays under the identity that measured it"),
        decisions,
    );
}

#[test]
fn cuda_only_acquired_peer_without_exact_identity_fails_closed() {
    let caps = test_hw_caps();
    let mut profile = AutorouteHostProfile::from_caps(
        &caps,
        Some(""),
        true,
        test_eligible_backends(Some(ScanBackend::GpuCuda)),
    );
    profile.cpu_model = Some("test-cpu".to_string());

    assert_eq!(profile.gpu_name.as_deref(), Some(""));
    assert_eq!(
        profile.require_exact_identity(),
        Err("GPU device identity is unavailable")
    );
}

#[test]
fn hardware_cuda_identity_survives_a_software_wgpu_probe() {
    let mut caps = test_hw_caps();
    caps.gpu_available = true;
    caps.gpu_name = Some("llvmpipe (LLVM 15.0.7)".to_string());
    caps.gpu_runtime_identity = Some("wgpu:Vulkan:llvmpipe:mesa".to_string());
    caps.gpu_is_software = true;
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
    assert!(
        !profile.gpu_is_software,
        "an eligible CUDA peer must not inherit the unrelated WGPU software flag"
    );
    profile
        .require_exact_identity()
        .expect("hardware CUDA plus software WGPU must retain exact CUDA identity");
}

#[test]
fn gpu_candidate_eligibility_requires_hardware_and_complete_identity() {
    let complete = keyhog_scanner::GpuBackendCandidateStatus {
        backend: ScanBackend::GpuWgpu,
        available: true,
        acquired: true,
        driver_id: Some("wgpu"),
        driver_version: Some("0.6.4"),
        device_identity: Some("NVIDIA RTX 5090:10de:2b85".to_string()),
        runtime_identity: Some("Vulkan:NVIDIA:570.211.01".to_string()),
        is_software: false,
        acquisition_error: None,
    };
    assert!(complete.is_eligible());

    let mut software = complete.clone();
    software.is_software = true;
    assert!(!software.is_eligible());

    let mut incomplete = complete;
    incomplete.runtime_identity = None;
    assert!(!incomplete.is_eligible());
}

#[test]
fn gpu_excluded_calibration_collapses_an_already_acquired_peer() {
    // Regression: diagnostic calibration can exclude GPU after scanner startup
    // has acquired a physical peer. Every GPU identity field must collapse
    // together or exact identity rejects runtime-without-device state.
    let mut gpu_host = test_hw_caps();
    gpu_host.gpu_available = true;
    gpu_host.gpu_name = Some("NVIDIA GeForce RTX 5090".to_string());
    gpu_host.gpu_runtime_identity = Some("wgpu:Vulkan:NVIDIA:565.00".to_string());
    gpu_host.gpu_is_software = false;

    // gpu_participates = false means this calibration cannot route to the GPU.
    // An already-acquired peer must also be excluded from the persisted host
    // identity for the CPU-only diagnostic route.
    let mut portable = AutorouteHostProfile::from_caps(
        &gpu_host,
        Some("gpu-cuda-region-presence:cuda@0.6.4:NVIDIA RTX 5090"),
        false,
        test_eligible_backends(None),
    );
    assert_eq!(
        portable.gpu_name, None,
        "GPU-excluded calibration records no GPU device identity"
    );
    assert_eq!(
        portable.gpu_runtime_backend, None,
        "GPU-excluded calibration records no GPU runtime backend"
    );
    assert_eq!(
        portable.gpu_driver_runtime_identity, None,
        "GPU-excluded calibration records no GPU driver identity"
    );
    assert_eq!(
        portable.gpu_batch_input_limit_bytes, None,
        "GPU-excluded calibration records no irrelevant accelerator dispatch cap"
    );
    assert!(
        !portable.gpu_is_software,
        "GPU-excluded calibration carries no GPU software flag"
    );
    // Isolate the GPU invariant from real-host cpuinfo so the test is hermetic.
    portable.cpu_model = Some("test-cpu".to_string());
    portable
        .require_exact_identity()
        .expect("GPU-excluded calibration must accept its CPU-only identity");

    // Contrast: a GPU-CAPABLE build whose runtime probe FAILED (gpu_backend
    // None) must STILL fail closed, the physical GPU IS usable by this build,
    // so caching GPU-absent evidence would silently mis-route (Law 10).
    let mut gpu_build_probe_failed =
        AutorouteHostProfile::from_caps(&gpu_host, None, true, test_eligible_backends(None));
    gpu_build_probe_failed.cpu_model = Some("test-cpu".to_string());
    assert_eq!(
        gpu_build_probe_failed.require_exact_identity(),
        Err("GPU runtime backend identity is unavailable"),
        "a GPU-capable build that sees the card but got no runtime backend must fail closed"
    );
}

#[test]
#[cfg(feature = "simd")]
fn cached_router_replays_cpu_identity_when_runtime_policy_disables_gpu() {
    let scanner = CompiledScanner::compile_with_gpu_policy(
        phase1_test_detectors(),
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    )
    .expect("compile CPU-policy scanner");
    let mut probed_caps = test_hw_caps();
    probed_caps.gpu_available = true;
    probed_caps.gpu_name = Some("NVIDIA GeForce RTX 5090".to_string());
    probed_caps.gpu_runtime_identity = Some("wgpu:Vulkan:NVIDIA:565.00".to_string());
    probed_caps.gpu_is_software = false;

    let host = AutorouteHostProfile::from_caps(
        &probed_caps,
        None,
        false,
        test_scanner_eligible_backends(&scanner, None),
    )
    .with_live_hyperscan(scanner.simd_backend_available());
    let directory = tempfile::tempdir().expect("CPU-policy autoroute cache directory");
    let path = directory.path().join("autoroute.json");
    let config_digest = 0x6f4d_11c2_731a_b908;
    let batch = vec![test_chunk_with_source(
        "token = abc\n".repeat(64),
        "filesystem",
    )];
    let pattern_count = scanner.runtime_status().pattern_count;
    let admission_plan = scanner.phase1_admission_plan(&batch);
    let key = super::workload::workload_key(
        &batch,
        pattern_count,
        admission_plan.summary(),
        admission_plan.phase2_keyword_triggers(),
        scanner.decode_workload_plan(),
    )
    .expect("CPU-policy workload classified");
    let decisions = HashMap::from([(
        key,
        AutorouteDecision::new(
            if scanner.simd_backend_available() {
                ScanBackend::SimdCpu
            } else {
                ScanBackend::CpuFallback
            },
            batch[0].data.len() as u64,
            1,
            5,
            Some(8),
            None,
        ),
    )]);
    save_autoroute_cache(
        &path,
        autoroute_detector_digest(test_rules_digest()),
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect("persist CPU-policy autoroute decision");

    let router = CachedBackendRouter::new(
        probed_caps,
        pattern_count,
        test_rules_digest().to_string(),
        config_digest,
        false,
        Ok(Some(path)),
        &scanner,
    );
    assert!(
        router.cache_load_error.is_none(),
        "disabled GPU policy must replay the CPU-only host identity even after hardware probing: {:?}",
        router.cache_load_error
    );
    assert_eq!(router.decisions.len(), 1);
}

#[test]
fn measured_router_collapses_stale_gpu_identity_when_runtime_policy_disables_gpu() {
    let scanner = CompiledScanner::compile_with_gpu_policy(
        phase1_test_detectors(),
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    )
    .expect("compile CPU-policy scanner");
    let mut probed_caps = test_hw_caps();
    probed_caps.gpu_available = true;
    probed_caps.gpu_name = Some("NVIDIA GeForce RTX 5090".to_string());
    probed_caps.gpu_runtime_identity = Some("wgpu:Vulkan:NVIDIA:565.00".to_string());

    let router = MeasuredBackendRouter::new(
        probed_caps,
        scanner.runtime_status().pattern_count,
        test_rules_digest().to_string(),
        0x5e21_97b4_80f3_4dc1,
        false,
        false,
        false,
        Ok(None),
        None,
        &scanner,
    );

    assert_eq!(router.host_profile.gpu_name, None);
    assert_eq!(router.host_profile.gpu_runtime_backend, None);
    assert_eq!(router.host_profile.gpu_driver_runtime_identity, None);
}

#[test]
fn gpu_capable_build_rejects_present_gpu_without_device_name() {
    let mut caps = test_hw_caps();
    caps.gpu_available = true;
    caps.gpu_name = None;
    caps.gpu_runtime_identity = Some("cuda:unknown-device:driver-565".to_string());

    let mut profile = AutorouteHostProfile::from_caps(
        &caps,
        Some(""),
        true,
        test_eligible_backends(Some(ScanBackend::GpuCuda)),
    );
    profile.cpu_model = Some("test-cpu".to_string());
    assert_eq!(profile.gpu_name.as_deref(), Some(""));
    assert_eq!(
        profile.require_exact_identity(),
        Err("GPU device identity is unavailable"),
        "present GPU hardware with a failed name probe must invalidate calibration, not collapse to no-GPU identity"
    );
}

#[test]
fn missing_autoroute_cache_does_not_require_gpu_runtime_identity() {
    let dir = tempfile::TempDir::new().expect("tempdir for missing autoroute cache");
    let path = dir.path().join("missing-autoroute-cache.json");
    let mut host = test_host(Some("NVIDIA GeForce RTX 5090"));
    host.gpu_runtime_backend = None;
    host.gpu_driver_runtime_identity = None;

    let (loaded_path, decisions, cache_load_error) = load_persistent_autoroute_decisions(
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &host,
        Ok(Some(path.clone())),
    );

    assert_eq!(loaded_path, Some(path));
    assert!(
        decisions.is_empty(),
        "missing cache file cannot produce route decisions"
    );
    assert_eq!(
        cache_load_error, None,
        "a missing cache file must surface as a missing-cache autoroute state, \
         not as a GPU host-identity failure"
    );
}
