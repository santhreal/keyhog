use super::evidence::{
    canonical_matches, canonical_matches_equal_reference, AutorouteCalibrationPoint,
    AutorouteDecision, BackendTimingEvidence, MeasuredRoute, RouteTimingEvidence,
};
use super::host::AutorouteHostProfile;
use super::store::{
    inspect_autoroute_cache, load_autoroute_cache, resolve_bucket, save_autoroute_cache,
    AutorouteBuildFeatures, AutorouteCache, AutorouteCacheSaveOutcome, BucketResolution,
    AUTOROUTE_CACHE_FILE_BYTES,
};
use super::workload::{
    autoroute_stable_bucket, autoroute_stable_decode_bucket, decode_workload_projection,
    decode_workload_sketch as decode_workload_sketch_with_plan, planned_decode_sample_bytes,
    planned_decode_sample_quotas, render_workload_key, source_class_id, source_class_label,
    source_mixture_key, test_measurement_shape_evidence, validate_source_mixture_key,
    validate_workload_source_mixture, workload_evidence_digest,
    workload_key as workload_key_with_plan, Phase1AdmissionKey, SourceMixtureEntry,
    SourceMixtureKey, WorkloadKey,
};
use super::*;

fn route_timings(
    simd: BackendTimingEvidence,
    cpu: Option<BackendTimingEvidence>,
    cuda: Option<BackendTimingEvidence>,
    wgpu: Option<BackendTimingEvidence>,
    simd_plain: Option<BackendTimingEvidence>,
    cpu_plain: Option<BackendTimingEvidence>,
    cuda_plain: Option<BackendTimingEvidence>,
    wgpu_plain: Option<BackendTimingEvidence>,
) -> Vec<RouteTimingEvidence> {
    let mut routes = Vec::new();
    for (backend, base, plain) in [
        (ScanBackend::SimdCpu, Some(simd), simd_plain),
        (ScanBackend::CpuFallback, cpu, cpu_plain),
        (ScanBackend::GpuCuda, cuda, cuda_plain),
        (ScanBackend::GpuWgpu, wgpu, wgpu_plain),
    ] {
        let Some(base) = base else {
            continue;
        };
        // LAW10: no runtime effect; test-only fixtures synthesize omitted timing, and production decisions never use this constructor.
        let plain = plain.unwrap_or_else(|| {
            BackendTimingEvidence::constant_ms(
                base.median_ms().saturating_add(1_000),
                AUTOROUTE_CALIBRATION_TRIALS,
            )
        });
        for (phase2_plain_localizer, phase2_keyword_localizer, timing) in [
            (false, false, base.clone()),
            (true, false, plain.clone()),
            (
                false,
                true,
                BackendTimingEvidence::constant_ms(
                    base.median_ms().saturating_add(2_000),
                    AUTOROUTE_CALIBRATION_TRIALS,
                ),
            ),
            (
                true,
                true,
                BackendTimingEvidence::constant_ms(
                    plain.median_ms().saturating_add(2_000),
                    AUTOROUTE_CALIBRATION_TRIALS,
                ),
            ),
        ] {
            routes.push(RouteTimingEvidence::new(
                MeasuredRoute {
                    backend,
                    phase2_plain_localizer,
                    phase2_keyword_localizer,
                },
                timing,
            ));
        }
    }
    routes
}

fn route_timing_mut(
    point: &mut AutorouteCalibrationPoint,
    backend: ScanBackend,
    phase2_plain_localizer: bool,
    phase2_keyword_localizer: bool,
) -> &mut BackendTimingEvidence {
    &mut point
        .route_timings
        .iter_mut()
        .find(|entry| {
            entry.backend == backend.label()
                && entry.phase2_plain_localizer == phase2_plain_localizer
                && entry.phase2_keyword_localizer == phase2_keyword_localizer
        })
        .expect("test route timing exists")
        .timing
}

fn test_decode_workload_plan() -> keyhog_scanner::decode::DecodeWorkloadPlan {
    keyhog_scanner::decode::DecodeWorkloadPlan::from_limits(1, usize::MAX)
}

fn test_eligible_backends(gpu: Option<ScanBackend>) -> Vec<String> {
    let mut labels = vec![
        ScanBackend::SimdCpu.label().to_string(),
        ScanBackend::CpuFallback.label().to_string(),
    ];
    if let Some(gpu) = gpu {
        labels.push(gpu.label().to_string());
    }
    labels.sort_unstable();
    labels
}

#[cfg(feature = "simd")]
fn test_scanner_eligible_backends(
    scanner: &CompiledScanner,
    gpu: Option<ScanBackend>,
) -> Vec<String> {
    let mut labels = vec![ScanBackend::CpuFallback.label().to_string()];
    if scanner.simd_backend_available() {
        labels.push(ScanBackend::SimdCpu.label().to_string());
    }
    if let Some(gpu) = gpu {
        labels.push(gpu.label().to_string());
    }
    labels.sort_unstable();
    labels
}

#[test]
fn eligible_backend_labels_use_the_simd_plan_without_materializing_it() {
    let scanner = phase1_test_scanner();
    assert!(!scanner.simd_backend_initialized());
    let labels = super::eligible_backend_labels(&scanner, false);
    assert!(
        labels.contains(&ScanBackend::CpuFallback.label().to_string()),
        "the scalar CPU backend is always an eligible calibration peer"
    );
    assert_eq!(
        labels.contains(&ScanBackend::SimdCpu.label().to_string()),
        scanner.simd_backend_available(),
        "autoroute candidate census must reflect the canonical Hyperscan plan, not only the compiled feature"
    );
    assert!(
        !scanner.simd_backend_initialized(),
        "candidate census must not materialize Hyperscan"
    );
}

fn workload_key(
    batch: &[Chunk],
    pattern_count: usize,
) -> Result<WorkloadKey, super::workload::WorkloadClassificationError> {
    workload_key_with_plan(
        batch,
        pattern_count,
        all_admitted_phase1(batch),
        test_decode_workload_plan(),
    )
}

fn all_admitted_phase1(batch: &[Chunk]) -> keyhog_scanner::Phase1AdmissionSummary {
    keyhog_scanner::Phase1AdmissionSummary::all_admitted(
        batch.len() as u64,
        batch.iter().map(|chunk| chunk.data.len() as u64).sum(),
    )
}

fn phase1_test_scanner() -> CompiledScanner {
    CompiledScanner::compile(phase1_test_detectors()).expect("autoroute phase-1 scanner compiles")
}

fn phase1_test_detectors() -> Vec<keyhog_core::DetectorSpec> {
    vec![keyhog_core::DetectorSpec {
        tests: Vec::new(),
        id: "autoroute-phase1-token".into(),
        name: "Autoroute phase 1 token".into(),
        service: "unit".into(),
        severity: keyhog_core::Severity::High,
        patterns: vec![keyhog_core::PatternSpec {
            regex: r"ghp_[A-Za-z0-9]{8}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        keywords: vec!["ghp_".into()],
        min_confidence: Some(0.0),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }]
}

fn repeated_to_len(seed: &str, len: usize) -> String {
    let mut value = seed.repeat(len.div_ceil(seed.len()));
    value.truncate(len);
    value
}

fn decode_workload_sketch(
    batch: &[Chunk],
) -> Result<
    keyhog_scanner::decode::DecodeAdmissionSketch,
    super::workload::WorkloadClassificationError,
> {
    decode_workload_sketch_with_plan(batch, test_decode_workload_plan())
}

/// `sole_compiled_backend` must short-circuit autoroute to the lone backend on a
/// build that compiled no backend choice (portable: no `simd`/`gpu`), and defer to
/// autoroute (return `None`) whenever a real choice exists. This is what keeps a
/// portable single-backend build from failing closed (exit 2) on an uncalibrated
/// workload (the Docker `musl` integration matrix is the end-to-end proof).
#[test]
fn sole_compiled_backend_tracks_the_feature_set() {
    let sole = super::sole_compiled_backend();
    if keyhog_scanner::hw_probe::multiple_backends_compiled() {
        assert_eq!(
            sole, None,
            "a build with a backend choice must defer to autoroute, not short-circuit"
        );
    } else {
        assert_eq!(
            sole,
            Some(ScanBackend::CpuFallback),
            "a single-backend (portable) build resolves its only backend without calibration"
        );
    }
}

#[test]
fn autoroute_build_identity_tracks_dependency_owned_backend_features() {
    let identity = AutorouteBuildFeatures::current();
    assert_eq!(
        identity.scanner_features.iter().any(|name| name == "gpu"),
        keyhog_scanner::hw_probe::gpu_backend_compiled(),
        "persisted autoroute identity must record the scanner dependency's actual GPU backend"
    );
    assert_eq!(
        identity.scanner_features.iter().any(|name| name == "simd"),
        keyhog_scanner::hw_probe::simd_backend_compiled(),
        "persisted autoroute identity must record the scanner dependency's actual SIMD backend"
    );

    for (feature, enabled) in [
        ("binary", cfg!(feature = "binary")),
        ("azure", cfg!(feature = "azure")),
        ("docker", cfg!(feature = "docker")),
        ("gcs", cfg!(feature = "gcs")),
        ("github", cfg!(feature = "github")),
        ("git", cfg!(feature = "git")),
        ("gitlab", cfg!(feature = "gitlab")),
        ("bitbucket", cfg!(feature = "bitbucket")),
        ("s3", cfg!(feature = "s3")),
        ("web", cfg!(feature = "web")),
    ] {
        assert_eq!(
            identity.sources_features.iter().any(|name| name == feature),
            enabled,
            "persisted autoroute identity must match the compiled `{feature}` source backend"
        );
    }

    for (feature, enabled) in [
        ("gitlab", cfg!(feature = "gitlab")),
        ("bitbucket", cfg!(feature = "bitbucket")),
    ] {
        assert_eq!(
            identity.cli_features.iter().any(|name| name == feature),
            enabled,
            "persisted autoroute identity must match the CLI `{feature}` feature"
        );
    }
    assert_eq!(
        identity.verifier_features.iter().any(|name| name == "live"),
        cfg!(feature = "verify"),
        "web-source support alone must not claim that live verification is compiled"
    );
}

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

fn test_host(gpu_name: Option<&str>) -> AutorouteHostProfile {
    AutorouteHostProfile {
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        cpu_model: Some("Test CPU 5.0GHz".to_string()),
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: true,
        has_avx512: false,
        has_neon: false,
        hyperscan_available: true,
        hyperscan_runtime_identity: Some("hyperscan-test-runtime-5.4.2".to_string()),
        gpu_name: gpu_name.map(str::to_string),
        gpu_runtime_backend: gpu_name
            .map(|name| format!("gpu-wgpu-region-presence:wgpu@0.6.4:{name}:535.00")),
        gpu_driver_runtime_identity: gpu_name
            .map(|name| format!("gpu-wgpu-region-presence:wgpu@0.6.4:{name}:535.00")),
        gpu_batch_input_limit_bytes: gpu_name.map(|_| 512 * 1024 * 1024),
        gpu_is_software: false,
        total_memory_mb: Some(65_536),
        eligible_backends: test_eligible_backends(gpu_name.map(|_| ScanBackend::GpuWgpu)),
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

fn test_workload_key() -> WorkloadKey {
    WorkloadKey {
        bytes_bucket: 24,
        chunks_bucket: 1,
        max_file_bucket: 24,
        pattern_bucket: 5,
        phase1: Phase1AdmissionKey {
            alphabet_rejected_chunks_bucket: 0,
            alphabet_rejected_bytes_bucket: 0,
            bigram_rejected_chunks_bucket: 0,
            bigram_rejected_bytes_bucket: 0,
            admitted_chunks_bucket: 1,
            admitted_bytes_bucket: 24,
        },
        decode_kind_mask: keyhog_scanner::decode::DecodeAdmissionSketch::BASE64,
        decode_candidate_count_bucket: 2,
        decode_candidate_bytes_bucket: 3,
        decode_unknown: false,
        source_mixture: test_source_mixture("filesystem"),
    }
}

fn test_source_mixture(source_class: &str) -> SourceMixtureKey {
    SourceMixtureKey {
        entries: vec![SourceMixtureEntry {
            source_class_digest: source_class_id(source_class),
            has_full_size: true,
            chunk_ratio: 1,
            payload_ratio: 1,
            max_span_bucket: 24,
        }],
    }
}

fn test_hw_caps() -> keyhog_scanner::hw_probe::HardwareCaps {
    keyhog_scanner::hw_probe::HardwareCaps {
        physical_cores: 8,
        logical_cores: 16,
        has_avx2: true,
        has_avx512: false,
        has_neon: false,
        gpu_available: false,
        gpu_name: None,
        gpu_vram_mb: None,
        gpu_runtime_identity: None,
        gpu_is_software: false,
        total_memory_mb: Some(65_536),
        io_uring_available: false,
        hyperscan_available: true,
        hyperscan_runtime_identity: Some("test-hyperscan".to_string()),
    }
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
    let key = workload_key_with_plan(
        &batch,
        pattern_count,
        scanner.phase1_admission_summary(&batch),
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
        scanner.runtime_status().detector_digest,
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
        super::host::parse_cpuinfo_model(cpuinfo).as_deref(),
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
        super::host::parse_cpuinfo_model(cpuinfo).as_deref(),
        Some("ARMv7 Processor rev 5 (v7l)"),
        "textual Linux Processor entries remain valid when model name/hardware are absent"
    );
}

fn write_tampered_decision_cache(
    path: &std::path::Path,
    digest: u64,
    config_digest: u64,
    host: &AutorouteHostProfile,
    key: WorkloadKey,
    bad_decision: AutorouteDecision,
    expected_error: &str,
) {
    let mut bad_decisions = HashMap::new();
    bad_decisions.insert(key.clone(), bad_decision.clone());
    let save_error = save_autoroute_cache(
        path,
        digest,
        test_rules_digest(),
        config_digest,
        host,
        &bad_decisions,
    )
    .expect_err("cache writer must reject invalid autoroute decision evidence")
    .to_string();
    assert!(
        save_error.contains(expected_error),
        "cache writer error should contain {expected_error:?}, got {save_error:?}"
    );

    let mut valid_decisions = HashMap::new();
    valid_decisions.insert(key.clone(), valid_decision_for_host(host));
    save_autoroute_cache(
        path,
        digest,
        test_rules_digest(),
        config_digest,
        host,
        &valid_decisions,
    )
    .expect("valid autoroute cache should be writable before tampering");
    let mut cache: AutorouteCache =
        serde_json::from_slice(&std::fs::read(path).expect("autoroute cache JSON"))
            .expect("cache should deserialize before tampering");
    let config = cache
        .configs
        .first_mut()
        .expect("saved single-config cache has one config entry");
    let mut row = config.decisions[0].clone();
    row.workload = key;
    row.decision = bad_decision;
    row.workload_digest = workload_evidence_digest(&row.workload);
    config.decisions.clear();
    config.decisions.push(row);
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&cache).expect("tampered cache serializes"),
    )
    .expect("tampered cache writable");
}

fn valid_decision_for_host(host: &AutorouteHostProfile) -> AutorouteDecision {
    let timing = |ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS);
    let has = |backend: ScanBackend| {
        host.eligible_backends
            .iter()
            .any(|label| label == backend.label())
    };
    AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::SimdCpu,
        8 * 1024 * 1024,
        1,
        test_measurement_shape_evidence(8 * 1024 * 1024, 1),
        0xA11D_0B57_A11D_0B57,
        1,
        route_timings(
            timing(12),
            Some(timing(20)),
            has(ScanBackend::GpuCuda).then(|| timing(30)),
            has(ScanBackend::GpuWgpu).then(|| timing(40)),
            Some(timing(1_012)),
            Some(timing(1_020)),
            has(ScanBackend::GpuCuda).then(|| timing(1_030)),
            has(ScanBackend::GpuWgpu).then(|| timing(1_040)),
        ),
        false,
        false,
    )
}

fn test_rules_digest() -> &'static str {
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

fn test_chunk(data: String) -> Chunk {
    test_chunk_with_source(data, "filesystem")
}

fn test_chunk_with_source(data: String, source_type: &str) -> Chunk {
    let size = data.len() as u64;
    Chunk {
        data: data.into(),
        metadata: keyhog_core::ChunkMetadata {
            source_type: source_type.into(),
            size_bytes: Some(size),
            ..Default::default()
        },
    }
}

#[test]
fn measurement_shape_distinguishes_equal_size_payloads_without_order_noise() {
    let alpha = test_chunk("token=AAAAAAAAAAAAAAAA\n".to_string());
    let beta = test_chunk("token=BBBBBBBBBBBBBBBB\n".to_string());
    assert_eq!(alpha.data.len(), beta.data.len());

    let alpha_only =
        measurement_shape_evidence(std::slice::from_ref(&alpha)).expect("alpha measurement shape");
    let beta_only =
        measurement_shape_evidence(std::slice::from_ref(&beta)).expect("beta measurement shape");
    assert_ne!(alpha_only.payload_digest, beta_only.payload_digest);
    assert_ne!(alpha_only.shape_digest, beta_only.shape_digest);

    let forward = measurement_shape_evidence(&[alpha.clone(), beta.clone()])
        .expect("forward measurement shape");
    let reverse = measurement_shape_evidence(&[beta, alpha]).expect("reverse measurement shape");
    assert_eq!(forward, reverse, "producer order is not a scan-cost class");
}

#[test]
fn calibration_envelope_retains_equal_size_distinct_measurement_shapes() {
    let alpha = test_chunk("token=AAAAAAAAAAAAAAAA\n".to_string());
    let beta = test_chunk("token=BBBBBBBBBBBBBBBB\n".to_string());
    let sample_bytes = alpha.data.len() as u64;
    let mut first =
        AutorouteDecision::new(ScanBackend::SimdCpu, sample_bytes, 1, 8, Some(12), None);
    first.primary_point_mut().measurement_shape =
        measurement_shape_evidence(&[alpha]).expect("alpha measurement shape");
    let mut second =
        AutorouteDecision::new(ScanBackend::SimdCpu, sample_bytes, 1, 8, Some(12), None);
    second.primary_point_mut().measurement_shape =
        measurement_shape_evidence(&[beta]).expect("beta measurement shape");

    first
        .merge_calibration_point(second)
        .expect("same-band points with the same winner form one envelope");
    assert_eq!(first.calibration_points.len(), 2);
    assert_ne!(
        first.calibration_points[0].measurement_shape.shape_digest,
        first.calibration_points[1].measurement_shape.shape_digest,
    );
}

#[test]
fn workload_key_distinguishes_decoder_work_for_same_size_batches() {
    let encoded = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo".repeat(128);
    let mut plain = "id: x\npath: ./src\n".repeat((encoded.len() / 18) + 1);
    plain.truncate(encoded.len());
    let plain_key = workload_key(&[test_chunk(plain)], 902).expect("plain workload classified");
    let encoded_key =
        workload_key(&[test_chunk(encoded)], 902).expect("encoded workload classified");

    assert_eq!(plain_key.bytes_bucket, encoded_key.bytes_bucket);
    assert_eq!(plain_key.chunks_bucket, encoded_key.chunks_bucket);
    assert_eq!(plain_key.max_file_bucket, encoded_key.max_file_bucket);
    assert_eq!(plain_key.pattern_bucket, encoded_key.pattern_bucket);
    assert_eq!(plain_key.source_mixture, encoded_key.source_mixture);
    assert!(
        encoded_key.decode_candidate_bytes_bucket > plain_key.decode_candidate_bytes_bucket
            && encoded_key.decode_kind_mask & keyhog_scanner::decode::DecodeAdmissionSketch::BASE64
                != 0,
        "autoroute workload keys must separate decode-heavy inputs from same-size plain text"
    );
}

#[test]
fn workload_key_distinguishes_equal_8mib_phase1_admission_classes() {
    const BYTES: usize = 8 * 1024 * 1024;
    let scanner = phase1_test_scanner();
    let decode_disabled = keyhog_scanner::decode::DecodeWorkloadPlan::from_limits(0, usize::MAX);
    let alphabet_batch = vec![test_chunk("~".repeat(BYTES))];
    let bigram_batch = vec![test_chunk("g".repeat(BYTES))];
    let admitted_batch = vec![test_chunk(repeated_to_len("gh ", BYTES))];

    let alphabet_key = workload_key_with_plan(
        &alphabet_batch,
        scanner.runtime_status().pattern_count,
        scanner.phase1_admission_summary(&alphabet_batch),
        decode_disabled.clone(),
    )
    .expect("alphabet-rejected workload classifies");
    let bigram_key = workload_key_with_plan(
        &bigram_batch,
        scanner.runtime_status().pattern_count,
        scanner.phase1_admission_summary(&bigram_batch),
        decode_disabled.clone(),
    )
    .expect("bigram-rejected workload classifies");
    let admitted_key = workload_key_with_plan(
        &admitted_batch,
        scanner.runtime_status().pattern_count,
        scanner.phase1_admission_summary(&admitted_batch),
        decode_disabled,
    )
    .expect("admitted workload classifies");

    assert_ne!(alphabet_key.phase1, bigram_key.phase1);
    assert_ne!(alphabet_key.phase1, admitted_key.phase1);
    assert_ne!(bigram_key.phase1, admitted_key.phase1);
    for mut legacy_key in [alphabet_key, bigram_key] {
        legacy_key.phase1 = admitted_key.phase1;
        assert_eq!(
            legacy_key, admitted_key,
            "the equal-layout classes must differ only by scanner-owned phase-1 admission"
        );
    }
}

#[test]
fn workload_key_projects_scanner_owned_decoder_families() {
    use keyhog_scanner::decode::DecodeAdmissionSketch as Sketch;

    let plain = workload_key(&[test_chunk("ordinary prose. short words.".into())], 902)
        .expect("plain workload classified");
    assert_eq!(plain.decode_kind_mask, 0);
    assert_eq!(plain.decode_candidate_count_bucket, 0);
    assert_eq!(plain.decode_candidate_bytes_bucket, 0);
    assert!(!plain.decode_unknown);

    let sparse = workload_key(
        &[test_chunk("token = \"AK%49AQYLPMN5HFIQR7XYA\"".into())],
        902,
    )
    .expect("sparse URL workload classified");
    assert_eq!(sparse.decode_kind_mask, Sketch::URL);
    assert_eq!(sparse.decode_candidate_count_bucket, 1);
    assert_eq!(sparse.decode_candidate_bytes_bucket, 1);
    assert!(!sparse.decode_unknown);

    let fixtures = [
        (
            "reverse",
            "token = \"AYX7RQIFH5NMPLYQAIKA\"",
            Sketch::REVERSE,
        ),
        ("caesar", "token = \"FPNFNTXKTISS7JCFRUQJ\"", Sketch::CAESAR),
        ("z85", "token = \"k$:^nqcuN?o?)MpmOcDPh=%iG\"", Sketch::Z85),
        (
            "quoted-printable",
            "token = \"AK=49AQYLPMN5HFIQR7XYA\"",
            Sketch::QUOTED_PRINTABLE,
        ),
        (
            "mime",
            "Subject: =?UTF-8?Q?AK=49AQYLPMN5HFIQR7XYA?=",
            Sketch::MIME_ENCODED_WORD,
        ),
        (
            "json",
            r#"{"token":"AK\u0049AQYLPMN5HFIQR7XYA"}"#,
            Sketch::JSON,
        ),
        (
            "javascript-static",
            "String.fromCharCode(...data.map((byte,index)=>byte^key[index%key.length]))",
            Sketch::JAVASCRIPT_STATIC,
        ),
        (
            "dense-base64",
            "token = \"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\"",
            Sketch::BASE64,
        ),
        (
            "compressed-container",
            "token = \"H4sIAAAAAAAAA3P09nQMjPQJ8PUz9XDzDAwyj4h0BABAsjTDFAAAAA==\"",
            Sketch::COMPRESSED_CONTAINER,
        ),
    ];

    let mut projections = std::collections::BTreeSet::new();
    projections.insert((
        plain.decode_kind_mask,
        plain.decode_candidate_count_bucket,
        plain.decode_candidate_bytes_bucket,
        plain.decode_unknown,
    ));
    for (name, input, required_kind) in fixtures {
        let key = workload_key(&[test_chunk(input.to_string())], 902)
            .unwrap_or_else(|error| panic!("{name} workload failed: {error}")); // LAW10: test-only oracle has no runtime effect and prints the exact error
        assert_ne!(
            key.decode_kind_mask & required_kind,
            0,
            "{name} workload key omitted scanner decoder kind: {key:?}"
        );
        assert!(key.decode_candidate_count_bucket > 0, "{name}: {key:?}");
        assert!(key.decode_candidate_bytes_bucket > 0, "{name}: {key:?}");
        assert!(!key.decode_unknown, "built-in {name} became unknown");
        assert!(
            projections.insert((
                key.decode_kind_mask,
                key.decode_candidate_count_bucket,
                key.decode_candidate_bytes_bucket,
                key.decode_unknown,
            )),
            "{name} must have a distinct decode workload projection: {key:?}"
        );
    }
}

#[test]
fn unknown_decoder_sketch_maps_to_visible_conservative_workload_fields() {
    assert_eq!(
        decode_workload_projection(keyhog_scanner::decode::DecodeAdmissionSketch::UNKNOWN),
        (0, 8, 16, true)
    );
}

#[test]
fn disabled_or_ineligible_decode_work_contributes_exact_zero() {
    use keyhog_scanner::decode::{DecodeAdmissionSketch, DecodeWorkloadPlan};

    let batch = (0..1_000)
        .map(|_| test_chunk("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo".into()))
        .collect::<Vec<_>>();
    let disabled = DecodeWorkloadPlan::from_limits(0, usize::MAX);
    assert_eq!(
        decode_workload_sketch_with_plan(&batch, disabled.clone())
            .expect("disabled decode is classifiable"),
        DecodeAdmissionSketch::NONE,
        "disabled decode must neither consume sample budget nor project work"
    );
    let key = workload_key_with_plan(&batch, 902, all_admitted_phase1(&batch), disabled)
        .expect("disabled decode workload remains classifiable");
    assert_eq!(
        (
            key.decode_kind_mask,
            key.decode_candidate_count_bucket,
            key.decode_candidate_bytes_bucket,
            key.decode_unknown,
        ),
        (0, 0, 0, false)
    );

    let over_limit = DecodeWorkloadPlan::from_limits(1, 8);
    assert_eq!(
        decode_workload_sketch_with_plan(&batch[..1], over_limit)
            .expect("over-limit decode workload remains classifiable"),
        DecodeAdmissionSketch::NONE,
        "chunks the scanner cannot decode must not project decoder work"
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(1_000))]

    #[test]
    fn workload_key_is_permutation_invariant_across_decoder_shapes(
        shape_indices in proptest::collection::vec(0usize..9, 1..32)
    ) {
        const SHAPES: &[&str] = &[
            "ordinary prose. short words.",
            "token = \"AK%49AQYLPMN5HFIQR7XYA\"",
            "token = \"AYX7RQIFH5NMPLYQAIKA\"",
            "token = \"FPNFNTXKTISS7JCFRUQJ\"",
            "token = \"k$:^nqcuN?o?)MpmOcDPh=%iG\"",
            "token = \"AK=49AQYLPMN5HFIQR7XYA\"",
            "Subject: =?UTF-8?Q?AK=49AQYLPMN5HFIQR7XYA?=",
            r#"{"token":"AK\u0049AQYLPMN5HFIQR7XYA"}"#,
            "token = \"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\"",
        ];
        let forward = shape_indices
            .iter()
            .map(|index| test_chunk(SHAPES[*index].to_string()))
            .collect::<Vec<_>>();
        let mut reversed = forward.clone();
        reversed.reverse();
        let mut rotated = forward.clone();
        if !rotated.is_empty() {
            let by = rotated.len() / 2;
            rotated.rotate_left(by);
        }

        let expected = workload_key(&forward, 902).expect("forward workload classified");
        proptest::prop_assert_eq!(
            workload_key(&reversed, 902).expect("reversed workload classified"),
            expected.clone()
        );
        proptest::prop_assert_eq!(
            workload_key(&rotated, 902).expect("rotated workload classified"),
            expected
        );
    }
}

#[test]
fn workload_decode_sketch_is_invariant_to_batch_permutation() {
    let plain = test_chunk("source code and ordinary prose\n".repeat(4_096));
    let encoded = test_chunk("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=".repeat(2_048));
    let escaped = test_chunk("%7B%22secret%22%3A%22value%22%7D".repeat(2_048));

    let forward = workload_key(&[plain.clone(), encoded.clone(), escaped.clone()], 902)
        .expect("forward workload classifies");
    let rotated = workload_key(&[encoded.clone(), escaped.clone(), plain.clone()], 902)
        .expect("rotated workload classifies");
    let reversed =
        workload_key(&[escaped, encoded, plain], 902).expect("reversed workload classifies");

    assert_eq!(forward, rotated);
    assert_eq!(forward, reversed);
}

#[test]
fn workload_decode_sketch_samples_late_chunks_and_file_tails() {
    let encoded = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo".repeat(4_096);
    let plain_prefix = " ".repeat(128 * 1024);
    let same_size_plain = " ".repeat(plain_prefix.len() + encoded.len());
    let tail_heavy = format!("{plain_prefix}{encoded}");

    let plain_key =
        workload_key(&[test_chunk(same_size_plain)], 902).expect("plain workload classifies");
    let tail_key =
        workload_key(&[test_chunk(tail_heavy)], 902).expect("tail-heavy workload classifies");
    assert!(
        tail_key.decode_candidate_bytes_bucket > plain_key.decode_candidate_bytes_bucket,
        "encoded data beyond the old 64 KiB prefix must affect workload identity"
    );

    let late_plain = vec![
        test_chunk(" ".repeat(128 * 1024)),
        test_chunk(" ".repeat(encoded.len())),
    ];
    let late_encoded = vec![test_chunk(" ".repeat(128 * 1024)), test_chunk(encoded)];
    assert!(
        decode_workload_sketch(&late_encoded)
            .expect("late encoded batch classifies")
            .candidate_bytes()
            > decode_workload_sketch(&late_plain)
                .expect("late plain batch classifies")
                .candidate_bytes(),
        "a decode-heavy late chunk must not be hidden by earlier plain bytes"
    );
}

#[test]
fn decode_sketch_sample_plan_is_bounded_and_represents_short_chunks() {
    let lengths = [0usize, 1, 23, 24, 71, 72, 73, 4_096, 1024 * 1024];
    let batch = lengths
        .iter()
        .map(|&len| test_chunk("x".repeat(len)))
        .collect::<Vec<_>>();
    let quotas = planned_decode_sample_quotas(&batch).expect("sample plan fits");
    let sampled = planned_decode_sample_bytes(&batch).expect("sample plan fits");

    assert_eq!(sampled, quotas.iter().sum::<usize>());
    assert!(sampled <= 64 * 1024, "sample plan read {sampled} bytes");
    for (index, &len) in lengths.iter().enumerate().filter(|(_, len)| **len <= 72) {
        assert_eq!(
            quotas[index], len,
            "short chunk {index} must be sampled in full"
        );
    }
    assert!(
        quotas[lengths.len() - 1] > 72,
        "unused sampling capacity must flow to long chunks"
    );
}

#[test]
fn decode_sketch_does_not_join_candidates_across_sample_windows() {
    let fragments = (0..1_000)
        .map(|_| test_chunk("A".repeat(23)))
        .collect::<Vec<_>>();
    assert_eq!(
        decode_workload_sketch(&fragments)
            .expect("fragment batch classifies")
            .candidate_count(),
        1_000,
        "each real 23-byte base64 candidate must remain distinct across sample windows"
    );
}

#[test]
fn workload_decode_sketch_fails_closed_when_representative_sampling_cannot_fit() {
    let batch = (0..911)
        .map(|_| test_chunk("x".repeat(72)))
        .collect::<Vec<_>>();
    let error = workload_key(&batch, 902)
        .expect_err("autoroute must reject an under-represented decoder-work sample")
        .to_string();
    assert!(
        error.contains("65536-byte sampling cap")
            && error.contains("lower --fused-batch")
            && error.contains("recalibrate"),
        "sampling-budget failure must be explicit and actionable: {error}"
    );
}

#[test]
fn workload_key_coalesces_parallel_reader_adjacent_bucket_jitter() {
    assert_eq!(
        autoroute_stable_bucket(1_u64 << 26),
        autoroute_stable_bucket((1_u64 << 27) - 1),
        "adjacent aggregate byte buckets from parallel reader batch jitter must not invalidate calibration"
    );
    assert_ne!(
        autoroute_stable_bucket(1_u64 << 26),
        autoroute_stable_bucket(1_u64 << 27),
        "the next power-of-two scan band needs distinct autoroute evidence"
    );
    assert_eq!(
        autoroute_stable_decode_bucket(7),
        autoroute_stable_decode_bucket(8),
        "adjacent decode-work sample jitter must not invalidate calibration"
    );
}

#[test]
fn eight_mib_crossover_has_an_exact_power_of_two_band() {
    const MIB: u64 = 1024 * 1024;
    let crossover = autoroute_stable_bucket(8 * MIB);
    assert_ne!(autoroute_stable_bucket(8 * MIB - 1), crossover);
    assert_eq!(autoroute_stable_bucket(16 * MIB - 1), crossover);
    assert_ne!(autoroute_stable_bucket(16 * MIB), crossover);
}

#[test]
fn calibration_tree_representatives_cover_default_fused_residual_chunk_keys() {
    let representative_counts =
        (1..=crate::orchestrator_config::FUSED_BATCH_DEFAULT).collect::<Vec<_>>();
    let representative_keys = representative_counts
        .iter()
        .map(|&count| {
            let batch = (0..count)
                .map(|_| test_chunk("a".repeat(4 * 1024)))
                .collect::<Vec<_>>();
            workload_key(&batch, 902).expect("representative 4 KiB batch classifies")
        })
        .collect::<HashSet<_>>();

    assert_eq!(
        crate::orchestrator_config::FUSED_BATCH_DEFAULT,
        32,
        "install-time autoroute calibration representatives must be revisited if the default fused batch changes"
    );
    for count in 1..=crate::orchestrator_config::FUSED_BATCH_DEFAULT {
        let batch = (0..count)
            .map(|_| test_chunk("a".repeat(4 * 1024)))
            .collect::<Vec<_>>();
        let key = workload_key(&batch, 902).expect("4 KiB residual batch classifies");
        assert!(
            representative_keys.contains(&key),
            "install calibration representatives must cover {count} x 4 KiB residual fused batch key {key:?}"
        );
    }
}

#[test]
fn source_mixture_distinguishes_execution_subtypes_without_section_name_explosion() {
    let plain = source_mixture_key(&[
        test_chunk_with_source("a".repeat(64), "filesystem"),
        test_chunk_with_source("a".repeat(64), "filesystem"),
    ])
    .expect("filesystem source mixture classifies");
    let windowed = source_mixture_key(&[
        test_chunk_with_source("a".repeat(64), "filesystem/windowed"),
        test_chunk_with_source("a".repeat(64), "filesystem/windowed"),
    ])
    .expect("windowed filesystem source mixture classifies");
    let pdf = source_mixture_key(&[
        test_chunk_with_source("a".repeat(64), "filesystem/pdf"),
        test_chunk_with_source("a".repeat(64), "filesystem/pdf"),
    ])
    .expect("PDF filesystem source mixture classifies");
    let docker = source_mixture_key(&[
        test_chunk_with_source("a".repeat(64), "docker"),
        test_chunk_with_source("a".repeat(64), "docker"),
    ])
    .expect("docker source mixture classifies");

    assert_ne!(
        plain, windowed,
        "windowed extraction has a distinct execution shape from ordinary filesystem input"
    );
    assert_ne!(
        windowed, pdf,
        "windowed and PDF extraction must not reuse one another's route evidence"
    );
    assert_ne!(plain, docker);

    let web_js = source_mixture_key(&[test_chunk_with_source("a".repeat(64), "web:js")])
        .expect("web JavaScript classifies");
    let web_sourcemap =
        source_mixture_key(&[test_chunk_with_source("a".repeat(64), "web:sourcemap")])
            .expect("web source map classifies");
    assert_ne!(
        web_js, web_sourcemap,
        "colon-delimited web preprocessing classes must retain distinct route evidence"
    );

    let elf_text =
        source_mixture_key(&[test_chunk_with_source("a".repeat(64), "binary:elf:.text")])
            .expect("ELF text section classifies");
    let elf_rodata =
        source_mixture_key(&[test_chunk_with_source("a".repeat(64), "binary:elf:.rodata")])
            .expect("ELF rodata section classifies");
    let pe_text = source_mixture_key(&[test_chunk_with_source("a".repeat(64), "binary:pe:.text")])
        .expect("PE text section classifies");
    assert_eq!(
        elf_text, elf_rodata,
        "section names do not change the binary extraction execution shape"
    );
    assert_ne!(elf_text, pe_text, "binary formats remain distinct classes");

    let exif_metadata = source_mixture_key(&[test_chunk_with_source(
        "a".repeat(64),
        "filesystem/image-metadata/exif",
    )])
    .expect("EXIF image metadata classifies");
    let png_metadata = source_mixture_key(&[test_chunk_with_source(
        "a".repeat(64),
        "filesystem/image-metadata/png",
    )])
    .expect("PNG image metadata classifies");
    assert_eq!(
        exif_metadata, png_metadata,
        "metadata decoder names do not change the image-metadata execution shape"
    );
    assert_ne!(
        exif_metadata, plain,
        "image metadata extraction remains distinct from ordinary filesystem input"
    );
}

#[test]
fn workload_rendering_names_only_bundled_source_classes() {
    let known = workload_key(&[test_chunk_with_source("a".repeat(64), "filesystem")], 902)
        .expect("known source classifies");
    let known_digest = &known.source_mixture.entries[0].source_class_digest;
    assert_eq!(source_class_label(known_digest), Some("filesystem"));
    let known_rendered = render_workload_key(&known);
    assert!(known_rendered.contains(&format!(
        "filesystem@{}",
        keyhog_core::hex_encode(known_digest)
    )));

    let private_source = "custom://token-do-not-echo";
    let unknown = workload_key(
        &[test_chunk_with_source("a".repeat(64), private_source)],
        902,
    )
    .expect("library-provided source classifies");
    let unknown_digest = &unknown.source_mixture.entries[0].source_class_digest;
    assert_eq!(source_class_label(unknown_digest), None);
    let unknown_rendered = render_workload_key(&unknown);
    assert!(unknown_rendered.contains(&format!(
        "custom@{}",
        keyhog_core::hex_encode(unknown_digest)
    )));
    assert!(
        !unknown_rendered.contains(private_source),
        "arbitrary library metadata must not be echoed into operator-visible evidence"
    );
}

#[test]
fn workload_key_separates_full_source_size_from_payload_size_fallback() {
    let full_size = test_chunk_with_source("a".repeat(64), "filesystem");
    let mut transformed = full_size.clone();
    transformed.metadata.size_bytes = None;

    let full_key = workload_key(&[full_size], 902).expect("full-size workload classifies");
    let transformed_key =
        workload_key(&[transformed], 902).expect("payload-size workload classifies");

    assert_eq!(full_key.bytes_bucket, transformed_key.bytes_bucket);
    assert_eq!(full_key.max_file_bucket, transformed_key.max_file_bucket);
    assert_ne!(
        full_key.source_mixture, transformed_key.source_mixture,
        "autoroute must not reuse full-source measurements for stream/transformation payload sizes"
    );
}

#[test]
fn source_mixture_associates_size_provenance_with_each_source_class() {
    let mut filesystem = test_chunk_with_source("a".repeat(64), "filesystem/windowed");
    let mut web = test_chunk_with_source("b".repeat(64), "web:js");
    filesystem.metadata.size_bytes = None;
    let filesystem_payload = source_mixture_key(&[filesystem.clone(), web.clone()])
        .expect("mixed source mixture classifies");

    filesystem.metadata.size_bytes = Some(64);
    web.metadata.size_bytes = None;
    let web_payload =
        source_mixture_key(&[filesystem, web]).expect("reversed size provenance classifies");

    assert_ne!(
        filesystem_payload, web_payload,
        "equal source sets with different per-class size provenance need distinct calibration keys"
    );
}

#[test]
fn source_mixture_separates_inverse_shares_and_ignores_chunk_order() {
    let mixture = |total: usize, filesystem_chunks: usize| {
        (0..total)
            .map(|index| {
                test_chunk_with_source(
                    "x".repeat(64),
                    if index < filesystem_chunks {
                        "filesystem/windowed"
                    } else {
                        "web:js"
                    },
                )
            })
            .collect::<Vec<_>>()
    };
    let dominant_filesystem = mixture(32, 31);
    let dominant_web = mixture(32, 1);
    let filesystem_key = source_mixture_key(&dominant_filesystem).expect("31:1 classifies");
    let web_key = source_mixture_key(&dominant_web).expect("1:31 classifies");
    assert_ne!(filesystem_key, web_key, "inverse mixtures must not alias");

    let mut permuted = dominant_filesystem.clone();
    permuted.reverse();
    assert_eq!(
        source_mixture_key(&permuted).expect("permuted mixture classifies"),
        filesystem_key,
        "source mixture identity must be permutation invariant"
    );
    assert_ne!(
        source_mixture_key(&mixture(32, 30)).expect("30:2 classifies"),
        filesystem_key,
        "every different source proportion must change identity"
    );

    let formerly_aliased_17 = source_mixture_key(&mixture(1024, 17)).expect("17:1007 classifies");
    let formerly_aliased_18 = source_mixture_key(&mixture(1024, 18)).expect("18:1006 classifies");
    assert_ne!(
        formerly_aliased_17, formerly_aliased_18,
        "exact mixture identity must not alias proportions within an old 1/64 share bin"
    );

    let full_filesystem_key = workload_key(&dominant_filesystem, 902).expect("31:1 key classifies");
    let full_web_key = workload_key(&dominant_web, 902).expect("1:31 key classifies");
    assert_ne!(full_filesystem_key, full_web_key);
    let mut without_mixture = full_filesystem_key.clone();
    without_mixture.source_mixture = full_web_key.source_mixture.clone();
    assert_eq!(
        without_mixture, full_web_key,
        "equal-layout inverse batches must differ only in their exact source mixture"
    );
}

#[test]
fn source_mixture_validation_rejects_noncanonical_persisted_entries() {
    let mut key = SourceMixtureKey {
        entries: vec![
            test_source_mixture("web")
                .entries
                .into_iter()
                .next()
                .unwrap(),
            test_source_mixture("filesystem")
                .entries
                .into_iter()
                .next()
                .unwrap(),
        ],
    };
    key.entries.sort();
    key.entries.reverse();
    assert!(validate_source_mixture_key(&key).is_err());
    key.entries.sort();
    key.entries[0].chunk_ratio = 0;
    assert!(validate_source_mixture_key(&key).is_err());

    let mut unreduced = test_source_mixture("filesystem");
    unreduced.entries[0].chunk_ratio = 2;
    unreduced.entries[0].payload_ratio = 2;
    assert!(validate_source_mixture_key(&unreduced).is_err());

    let mut zero_payload = test_workload_key();
    zero_payload.source_mixture.entries[0].payload_ratio = 0;
    zero_payload.source_mixture.entries[0].max_span_bucket = 0;
    zero_payload.max_file_bucket = 0;
    assert!(validate_workload_source_mixture(&zero_payload).is_err());

    let mut impossible_payload_span = test_workload_key();
    impossible_payload_span.source_mixture.entries[0].has_full_size = false;
    impossible_payload_span.source_mixture.entries[0].max_span_bucket = 25;
    impossible_payload_span.max_file_bucket = 25;
    assert!(validate_workload_source_mixture(&impossible_payload_span).is_err());

    let mut mixed_impossible_span = test_workload_key();
    let mut payload_entry = test_source_mixture("web").entries.remove(0);
    payload_entry.has_full_size = false;
    payload_entry.max_span_bucket = 25;
    mixed_impossible_span
        .source_mixture
        .entries
        .push(payload_entry);
    mixed_impossible_span.source_mixture.entries.sort();
    mixed_impossible_span.max_file_bucket = 25;
    assert!(validate_workload_source_mixture(&mixed_impossible_span).is_err());

    let mut parent_mismatch = test_workload_key();
    parent_mismatch.source_mixture.entries[0].max_span_bucket = 23;
    assert!(validate_workload_source_mixture(&parent_mismatch).is_err());

    assert!(source_mixture_key(&[]).is_err());
    assert!(source_mixture_key(&[test_chunk(String::new())]).is_err());
    let source_classes = |count: usize| {
        (0..count)
            .map(|index| test_chunk_with_source("x".into(), &format!("source-{index}")))
            .collect::<Vec<_>>()
    };
    assert!(source_mixture_key(&source_classes(64)).is_ok());
    assert!(source_mixture_key(&source_classes(65)).is_err());
}

#[test]
fn exact_source_mixtures_survive_cache_replay_and_inspection() {
    let mixture = |filesystem_chunks: usize| {
        (0..32)
            .map(|index| {
                test_chunk_with_source(
                    "x".repeat(64),
                    if index < filesystem_chunks {
                        "filesystem/windowed"
                    } else {
                        "web:js"
                    },
                )
            })
            .collect::<Vec<_>>()
    };
    let filesystem_key = workload_key(&mixture(31), 902).expect("31:1 workload classifies");
    let web_key = workload_key(&mixture(1), 902).expect("1:31 workload classifies");
    let dir = tempfile::TempDir::new().expect("tempdir for exact mixture replay");
    let path = dir.path().join("mixtures.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let mut decisions = HashMap::new();
    decisions.insert(
        filesystem_key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 2_048, 32, 12, None, None),
    );
    decisions.insert(
        web_key.clone(),
        AutorouteDecision::new(ScanBackend::CpuFallback, 2_048, 32, 13, Some(7), None),
    );

    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect("inverse source mixtures persist");
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect("inverse source mixtures reload");
    assert_eq!(loaded, decisions);
    assert_eq!(
        loaded
            .get(&filesystem_key)
            .and_then(AutorouteDecision::backend),
        Some(ScanBackend::SimdCpu)
    );
    assert_eq!(
        loaded.get(&web_key).and_then(AutorouteDecision::backend),
        Some(ScanBackend::CpuFallback)
    );
    let unmeasured_key = workload_key(&mixture(30), 902).expect("30:2 workload classifies");
    assert!(
        resolve_persisted_route(
            &loaded,
            unmeasured_key,
            AutorouteRuntimeClass::OneShot,
            &Some(path.clone()),
            &None,
        )
        .is_err(),
        "an unmeasured neighboring mixture must fail closed"
    );

    let inspection = inspect_autoroute_cache(Some(&path));
    assert!(
        inspection.error.is_none(),
        "inspection: {:?}",
        inspection.error
    );
    let rows = &inspection.configs[0].decisions;
    assert_eq!(rows.len(), 2);
    assert_ne!(rows[0].workload, rows[1].workload);
    assert!(rows.iter().all(|row| {
        row.workload.contains("filesystem/windowed@") && row.workload.contains("web:js@")
    }));
    for row in rows {
        assert_eq!(row.source_mixture.len(), 2);
        let source_classes = row
            .source_mixture
            .iter()
            .filter_map(|entry| entry.source_class.as_deref())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            source_classes,
            BTreeSet::from(["filesystem/windowed", "web:js"])
        );
        assert!(row
            .source_mixture
            .iter()
            .all(|entry| entry.source_class_digest.len() == 64));
        assert!(row
            .source_mixture
            .iter()
            .all(|entry| entry.chunk_ratio > 0 && entry.payload_ratio > 0));
    }
    let inspection_json = serde_json::to_value(&inspection).expect("inspection serializes");
    let json_entries = inspection_json["configs"][0]["decisions"][0]["source_mixture"]
        .as_array()
        .expect("JSON inspection exposes source-mixture entries");
    assert_eq!(json_entries.len(), 2);
    assert!(json_entries[0]["source_class_digest"]
        .as_str()
        .is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        }));
    assert!(json_entries
        .iter()
        .all(|entry| entry["source_class"].as_str().is_some()));

    let mut cache: AutorouteCache = serde_json::from_slice(
        &std::fs::read(&path).expect("read exact-mixture cache for binding tamper"),
    )
    .expect("deserialize exact-mixture cache for binding tamper");
    let first_mixture = cache.configs[0].decisions[0]
        .workload
        .source_mixture
        .clone();
    let second_mixture = cache.configs[0].decisions[1]
        .workload
        .source_mixture
        .clone();
    cache.configs[0].decisions[0].workload.source_mixture = second_mixture;
    cache.configs[0].decisions[1].workload.source_mixture = first_mixture;
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&cache).expect("serialize relabeled workload evidence"),
    )
    .expect("write relabeled workload evidence");
    let error = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect_err("source-mixture relabeling must invalidate workload evidence")
        .to_string();
    assert!(error.contains("bound to a different workload key"));
}

#[test]
fn cache_rejects_noncanonical_source_mixture_on_save_and_load() {
    let batch = [
        test_chunk_with_source("x".repeat(64), "filesystem"),
        test_chunk_with_source("y".repeat(64), "web"),
    ];
    let valid_key = workload_key(&batch, 902).expect("mixed workload classifies");
    let mut invalid_key = valid_key.clone();
    invalid_key.source_mixture.entries.reverse();
    let decision = AutorouteDecision::new(ScanBackend::SimdCpu, 128, 2, 12, None, None);
    let dir = tempfile::TempDir::new().expect("tempdir for source-mixture rejection");
    let rejected_path = dir.path().join("rejected-save.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let invalid = HashMap::from([(invalid_key.clone(), decision.clone())]);
    let save_error = save_autoroute_cache(
        &rejected_path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &invalid,
    )
    .expect_err("noncanonical source mixture must fail before persistence")
    .to_string();
    assert!(save_error.contains("duplicate or not canonically sorted"));
    assert!(!rejected_path.exists());

    let tampered_path = dir.path().join("tampered-load.json");
    save_autoroute_cache(
        &tampered_path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &HashMap::from([(valid_key, decision)]),
    )
    .expect("valid source mixture persists before tampering");
    let mut cache: AutorouteCache = serde_json::from_slice(
        &std::fs::read(&tampered_path).expect("read valid source-mixture cache"),
    )
    .expect("deserialize valid source-mixture cache");
    cache.configs[0].decisions[0]
        .workload
        .source_mixture
        .entries
        .reverse();
    std::fs::write(
        &tampered_path,
        serde_json::to_vec_pretty(&cache).expect("serialize tampered source-mixture cache"),
    )
    .expect("write tampered source-mixture cache");
    let load_error = load_autoroute_cache(
        &tampered_path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
    )
    .expect_err("noncanonical persisted source mixture must fail closed")
    .to_string();
    assert!(load_error.contains("duplicate or not canonically sorted"));
    let inspection = inspect_autoroute_cache(Some(&tampered_path));
    assert!(inspection.error.is_some());
    assert!(inspection.configs.is_empty());
}

#[test]
fn mismatched_sample_evidence_never_clobbers_or_replays() {
    let dir = tempfile::TempDir::new().expect("tempdir for sample binding");
    let path = dir.path().join("sample-binding.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let valid = HashMap::from([(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    )]);
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &valid,
    )
    .expect("valid sample binding persists");
    let original = std::fs::read(&path).expect("read valid sample-bound cache");

    let mismatched = HashMap::from([(
        key,
        AutorouteDecision::new(ScanBackend::SimdCpu, 4 * 1024 * 1024, 1, 12, None, None),
    )]);
    let save_error = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &mismatched,
    )
    .expect_err("mismatched sample evidence must fail before persistence")
    .to_string();
    assert!(save_error.contains("does not match workload bands"));
    assert_eq!(
        std::fs::read(&path).expect("read cache after rejected replacement"),
        original,
        "a rejected save must preserve the prior cache byte-for-byte"
    );

    let mut cache: AutorouteCache =
        serde_json::from_slice(&original).expect("deserialize valid sample-bound cache");
    cache.configs[0].decisions[0]
        .decision
        .primary_point_mut()
        .sample_bytes = 4 * 1024 * 1024;
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&cache).expect("serialize tampered sample binding"),
    )
    .expect("write tampered sample binding");
    let load_error = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect_err("mismatched persisted sample evidence must fail closed")
        .to_string();
    assert!(load_error.contains("does not match workload bands"));
    let inspection = inspect_autoroute_cache(Some(&path));
    assert!(inspection.error.is_some());
    assert!(inspection.configs.is_empty());
}

#[test]
fn workload_key_rejects_missing_source_class_evidence() {
    let err = workload_key(&[test_chunk_with_source("a".repeat(64), "")], 902)
        .expect_err("autoroute must not hash missing source class as a reusable bucket");
    let text = err.to_string();
    assert!(
        text.contains("source_type") && text.contains("non-empty source execution class"),
        "missing source-class metadata must be an explicit autoroute evidence error, got: {text}"
    );
}

#[test]
fn autoroute_calibration_rejects_empty_sample_before_timing() {
    for sample in [Vec::new(), vec![test_chunk(String::new())]] {
        let err = calibration::calibration_sample_bytes(&sample)
            .expect_err("empty/zero-byte calibration sample must be rejected");
        let text = err.to_string();
        assert!(
            text.contains("calibration sample is insufficient")
                && text.contains("non-empty scan bytes"),
            "autoroute calibration must fail before timing an invalid sample; got: {text}"
        );
    }

    assert_eq!(
        calibration::calibration_sample_bytes(&[test_chunk("abc".to_string())])
            .expect("non-empty sample is usable"),
        3
    );
}

#[test]
fn autoroute_calibration_counts_full_batch_bytes() {
    let batch = [
        test_chunk("a".repeat(8 * 1024 * 1024)),
        test_chunk("b".repeat(1024)),
    ];

    assert_eq!(
        calibration::calibration_sample_bytes(&batch).expect("non-empty full batch is usable"),
        (8 * 1024 * 1024 + 1024) as u64,
        "autoroute calibration evidence must count the keyed full batch, not the retired 8 MiB prefix sample"
    );
}

#[test]
fn autoroute_cache_roundtrip_and_digest_invalidation() {
    let path =
        std::env::temp_dir().join(format!("keyhog_autoroute_test_{}.json", std::process::id()));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    let timing = |ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS);
    let localizer_winner = |sample_bytes, simd_ms, localizer_ms, gpu_ms| {
        let mut decision = AutorouteDecision::from_peer_timing_evidence(
            ScanBackend::SimdCpu,
            sample_bytes,
            1,
            test_measurement_shape_evidence(sample_bytes, 1),
            0xA11D_0B57_A11D_0B57,
            1,
            route_timings(
                timing(simd_ms),
                Some(timing(simd_ms + 8)),
                None,
                Some(timing(gpu_ms)),
                Some(timing(localizer_ms)),
                Some(timing(localizer_ms + 8)),
                None,
                Some(timing(gpu_ms + 1)),
            ),
            false,
            false,
        );
        decision.phase2_plain_localizer = true;
        decision
    };
    let mut size_envelope = localizer_winner(8 * 1024 * 1024, 12, 7, 40);
    size_envelope
        .merge_calibration_point(localizer_winner(12 * 1024 * 1024, 13, 8, 41))
        .expect("same-winner size evidence forms one persisted envelope");
    decisions.insert(key.clone(), size_envelope);

    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .unwrap();
    let serialized = std::fs::read_to_string(&path).expect("autoroute cache JSON");
    let version_field = format!("\"version\": {AUTOROUTE_CACHE_VERSION}");
    assert!(
        serialized.contains(&version_field)
            && serialized.contains("\"build_features\"")
            && serialized.contains("\"cli_features\"")
            && serialized.contains("\"scanner_features\"")
            && serialized.contains("\"sources_features\"")
            && serialized.contains("\"verifier_features\"")
            && serialized.contains("\"executable_sha256\"")
            && serialized.contains("\"rules_digest\"")
            && serialized.contains("\"cpu_model\"")
            && serialized.contains("\"physical_cores\"")
            && serialized.contains("\"logical_cores\"")
            && serialized.contains("\"total_memory_mb\"")
            && serialized.contains("\"hyperscan_runtime_identity\"")
            && serialized.contains("\"gpu_runtime_backend\"")
            && serialized.contains("\"gpu_driver_runtime_identity\"")
            && serialized.contains("\"gpu_batch_input_limit_bytes\"")
            && serialized.contains("\"decode_kind_mask\"")
            && serialized.contains("\"decode_candidate_count_bucket\"")
            && serialized.contains("\"decode_candidate_bytes_bucket\"")
            && serialized.contains("\"decode_unknown\"")
            && !serialized.contains("\"decode_density_bucket\"")
            && serialized.contains("\"candidate_receipts\"")
            && serialized.contains("\"phase2_plain_localizer\": true")
            && serialized.contains("\"phase2_keyword_localizer\": false")
            && serialized.contains("\"correctness_digest\"")
            && serialized.contains("\"completed_trials\"")
            && serialized.contains("\"evidence_digest\"")
            && serialized.contains("\"calibrated_at_unix_ms\"")
            && serialized.contains("\"route_timings\"")
            && !serialized.contains("\"simd_timing\"")
            && serialized.contains("\"trials_ns\"")
            && !serialized.contains("\"confidence_interval_95_ns\"")
            && !serialized.contains("\"best_ns\"")
            && !serialized.contains("\"mean_ns\""),
        // v31 persists primary timing evidence, workload binding, and per-candidate parity receipts.
        // GPU cold/warm/route, and selected-margin keys are derived from the
        // trial vectors on load, never stored.
        "cache JSON must persist route timing evidence, not only the selected backend"
    );
    let loaded =
        load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host).unwrap();
    assert_eq!(loaded, decisions);
    let replayed = resolve_persisted_route(
        &loaded,
        key.clone(),
        AutorouteRuntimeClass::OneShot,
        &Some(path.clone()),
        &None,
    )
    .expect("persisted localization plan replays");
    assert_eq!(replayed.backend, ScanBackend::SimdCpu);
    assert!(replayed.phase2_plain_localizer);
    assert!(!replayed.phase2_keyword_localizer);
    let inspection = inspect_autoroute_cache(Some(&path));
    assert_eq!(inspection.error, None);
    assert_eq!(inspection.configs.len(), 1);
    assert_eq!(inspection.configs[0].decisions[0].calibration_points, 2);
    assert!(inspection.configs[0].decisions[0].phase2_plain_localizer);
    assert!(!inspection.configs[0].decisions[0].phase2_keyword_localizer);
    assert!(inspection.configs[0].decisions[0]
        .measured_points
        .iter()
        .all(|point| point.one_shot_phase2_plain_localizer));
    assert!(inspection.configs[0].decisions[0]
        .measured_points
        .iter()
        .all(|point| !point.one_shot_phase2_keyword_localizer));
    let expected_route_timings = inspection.configs[0].eligible_backends.len() * 4;
    assert!(inspection.configs[0].decisions[0]
        .measured_points
        .iter()
        .all(|point| point.route_timings.len() == expected_route_timings));
    let first_point = &inspection.configs[0].decisions[0].measured_points[0];
    let first_shape = test_measurement_shape_evidence(8 * 1024 * 1024, 1);
    assert_eq!(first_point.measurement_generator, first_shape.generator);
    assert_eq!(
        first_point.payload_digest,
        keyhog_core::hex_encode(&first_shape.payload_digest)
    );
    assert_eq!(
        first_point.measurement_shape_digest,
        keyhog_core::hex_encode(&first_shape.shape_digest)
    );
    let simd_plain = first_point
        .route_timings
        .iter()
        .find(|timing| {
            timing.backend == ScanBackend::SimdCpu.label()
                && timing.phase2_plain_localizer
                && !timing.phase2_keyword_localizer
        })
        .expect("inspection exposes the measured SIMD localizer route");
    assert_eq!(
        simd_plain.trials_ns,
        vec![7_000_000; AUTOROUTE_CALIBRATION_TRIALS]
    );
    assert_eq!(simd_plain.cold_ns, Some(7_000_000));
    assert_eq!(simd_plain.one_shot_ns, 7_000_000);
    assert_eq!(simd_plain.one_shot_ci95_low_ns, 7_000_000);
    assert_eq!(simd_plain.one_shot_ci95_high_ns, 7_000_000);
    assert_eq!(simd_plain.warm_ns, Some(7_000_000));
    assert_eq!(simd_plain.warm_ci95_low_ns, Some(7_000_000));
    assert_eq!(simd_plain.warm_ci95_high_ns, Some(7_000_000));
    let scalar_plain = first_point
        .route_timings
        .iter()
        .find(|timing| {
            timing.backend == ScanBackend::CpuFallback.label()
                && timing.phase2_plain_localizer
                && !timing.phase2_keyword_localizer
        })
        .expect("inspection exposes the measured scalar localizer route");
    assert_eq!(scalar_plain.cold_ns, None);
    assert_eq!(scalar_plain.warm_ns, None);
    assert_eq!(inspection.configs[0].decisions[0].measured_points.len(), 2);
    assert_eq!(
        inspection.configs[0].decisions[0]
            .measured_points
            .iter()
            .map(|point| point.sample_bytes)
            .collect::<Vec<_>>(),
        vec![8 * 1024 * 1024, 12 * 1024 * 1024]
    );
    assert_eq!(
        inspection.configs[0].decisions[0].sample_bytes_min,
        8 * 1024 * 1024
    );
    assert_eq!(
        inspection.configs[0].decisions[0].sample_bytes_max,
        12 * 1024 * 1024
    );
    assert_eq!(
        inspection.configs[0].hyperscan_runtime_identity,
        host.hyperscan_runtime_identity
    );
    assert_eq!(
        inspection.configs[0].gpu_batch_input_limit_bytes, host.gpu_batch_input_limit_bytes,
        "inspection must expose the exact cap that shaped GPU dispatch during calibration"
    );

    let mut replacement = HashMap::new();
    replacement.insert(
        key.clone(),
        AutorouteDecision::new(
            ScanBackend::CpuFallback,
            8 * 1024 * 1024,
            1,
            12,
            Some(8),
            Some(40),
        ),
    );
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &replacement,
    )
    .unwrap();
    let replaced =
        load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host).unwrap();
    assert_eq!(
        replaced, replacement,
        "autoroute recalibration must atomically replace an existing cache path"
    );

    let wrong = load_autoroute_cache(
        &path,
        digest.wrapping_add(1),
        test_rules_digest(),
        config_digest,
        &host,
    );
    assert!(
        wrong.is_err(),
        "cache must reject a different detector digest"
    );
    let wrong_rules = load_autoroute_cache(
        &path,
        digest,
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        config_digest,
        &host,
    );
    assert!(
        wrong_rules.is_err(),
        "cache must reject a different detector rules digest"
    );
    let wrong_config = load_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest.wrapping_add(1),
        &host,
    );
    assert!(
        wrong_config.is_err(),
        "cache must reject a different resolved scan config digest"
    );
    let mut other_host = host.clone();
    other_host.gpu_name = Some("NVIDIA GeForce RTX 4090".to_string());
    let wrong_host = load_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &other_host,
    );
    assert!(
        wrong_host.is_err(),
        "cache must reject a different host profile"
    );
    let mut other_hyperscan_runtime = host.clone();
    other_hyperscan_runtime.hyperscan_runtime_identity =
        Some("hyperscan-test-runtime-5.4.3".to_string());
    assert!(
        load_autoroute_cache(
            &path,
            digest,
            test_rules_digest(),
            config_digest,
            &other_hyperscan_runtime,
        )
        .is_err(),
        "cache must reject timing evidence from a different Hyperscan/Vectorscan runtime"
    );
    assert_eq!(
        load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
            .expect("the original linked-runtime identity must still replay"),
        replacement,
    );
    let mut other_gpu_batch_limit = host.clone();
    other_gpu_batch_limit.gpu_batch_input_limit_bytes = Some(256 * 1024 * 1024);
    assert!(
        load_autoroute_cache(
            &path,
            digest,
            test_rules_digest(),
            config_digest,
            &other_gpu_batch_limit,
        )
        .is_err(),
        "cache must reject timing evidence measured with a different resolved GPU batch cap"
    );
    assert_eq!(
        load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
            .expect("the original GPU batch-cap identity must still replay"),
        replacement,
    );
    let mut other_gpu_runtime = host.clone();
    other_gpu_runtime.gpu_driver_runtime_identity =
        Some("wgpu:Vulkan:Different:536.00".to_string());
    let wrong_gpu_runtime = load_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &other_gpu_runtime,
    );
    assert!(
        wrong_gpu_runtime.is_err(),
        "cache must reject a different GPU driver/runtime identity"
    );
    let mut other_runtime_backend = host.clone();
    other_runtime_backend.gpu_runtime_backend = Some("vulkan".to_string());
    let wrong_runtime_backend = load_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &other_runtime_backend,
    );
    assert!(
        wrong_runtime_backend.is_err(),
        "cache must reject a different GPU runtime backend"
    );
    let mut other_cpu = host.clone();
    other_cpu.cpu_model = Some("Test CPU 4.0GHz".to_string());
    let wrong_cpu = load_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &other_cpu,
    );
    assert!(
        wrong_cpu.is_err(),
        "cache must reject a different CPU model"
    );

    let mut tampered: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("cache must remain readable"))
            .expect("cache must remain JSON");
    tampered["executable_sha256"] = serde_json::json!("00".repeat(32));
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&tampered).expect("tampered cache must serialize"),
    )
    .expect("tampered cache must write");
    let wrong_artifact =
        load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
            .expect_err("cache from another executable artifact must fail closed");
    assert!(
        wrong_artifact
            .to_string()
            .contains("executable digest mismatch"),
        "artifact mismatch must be explicit: {wrong_artifact}"
    );

    // LAW10: no runtime effect; cleanup targets a disposable test path and cannot affect scanner findings.
    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn concurrent_autoroute_calibrations_preserve_every_config() {
    const WRITERS: usize = 16;
    let dir = tempfile::tempdir().expect("autoroute cache tempdir");
    let path = dir.path().join("autoroute.json");
    let host = test_host(None);
    let detector_digest = 0x1234_5678_9ABC_DEF0u64;
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));

    let writers = (0..WRITERS)
        .map(|index| {
            let path = path.clone();
            let host = host.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut decisions = HashMap::new();
                decisions.insert(test_workload_key(), cpu_decision(ScanBackend::SimdCpu));
                barrier.wait();
                save_autoroute_cache(
                    &path,
                    detector_digest,
                    test_rules_digest(),
                    0xCA11_0000 + index as u64,
                    &host,
                    &decisions,
                )
            })
        })
        .collect::<Vec<_>>();
    for writer in writers {
        writer
            .join()
            .expect("calibration writer thread")
            .expect("calibration cache save");
    }

    let bytes = std::fs::read(&path).expect("merged autoroute cache");
    let cache: AutorouteCache = serde_json::from_slice(&bytes).expect("valid autoroute cache JSON");
    let configs = cache
        .configs
        .iter()
        .map(|config| config.config_digest)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        configs.len(),
        WRITERS,
        "concurrent calibration processes must not lose one another's read/merge/write updates"
    );
    for index in 0..WRITERS {
        assert!(configs.contains(&(0xCA11_0000 + index as u64)));
    }
}

#[test]
fn multi_config_cache_accumulates_buckets_across_sequential_saves() {
    // Keystone regression. Each install-time calibration probe runs as a
    // SEPARATE process persisting one workload bucket. With the old overwrite
    // save, probe 2 evicted probe 1's bucket, so every other-sized scan failed
    // closed (exit 2). The merge save must UNION buckets for the same resolved
    // config across sequential saves.
    let dir = tempfile::TempDir::new().expect("tempdir for accumulation");
    let path = dir.path().join("accumulate-autoroute-cache.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);

    let small_key = test_workload_key();
    let mut large_key = small_key.clone();
    large_key.bytes_bucket = large_key.bytes_bucket.saturating_add(3);
    large_key.max_file_bucket = large_key.max_file_bucket.saturating_add(3);
    large_key.phase1.admitted_bytes_bucket =
        large_key.phase1.admitted_bytes_bucket.saturating_add(3);
    large_key.source_mixture.entries[0].max_span_bucket = large_key.source_mixture.entries[0]
        .max_span_bucket
        .saturating_add(3);
    assert_ne!(
        small_key, large_key,
        "test needs two distinct workload buckets"
    );

    let mut first = HashMap::new();
    first.insert(
        small_key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &first,
    )
    .expect("first sequential calibration persists");

    let mut second = HashMap::new();
    second.insert(
        large_key.clone(),
        AutorouteDecision::new(
            ScanBackend::CpuFallback,
            64 * 1024 * 1024,
            1,
            13,
            Some(7),
            None,
        ),
    );
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &second,
    )
    .expect("second sequential calibration persists");

    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect("accumulated cache reloads");
    assert!(
        loaded.contains_key(&small_key),
        "merge save must not evict the first probe's bucket"
    );
    assert!(
        loaded.contains_key(&large_key),
        "merge save must persist the second probe's bucket"
    );
    assert_eq!(
        loaded.len(),
        2,
        "both sequentially-calibrated buckets must coexist in one config entry"
    );
}

#[test]
fn multi_config_cache_keeps_distinct_presets_side_by_side() {
    // The default scan policy and a `--fast`/`--deep`/`--precision` preset
    // resolve to DIFFERENT config digests. Calibrating one must not evict the
    // other, or a documented preset fails closed after a clean install.
    let dir = tempfile::TempDir::new().expect("tempdir for preset coexistence");
    let path = dir.path().join("coexist-autoroute-cache.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let default_config = 0xD3FA_0117_D3FA_0117u64;
    let fast_config = 0xFA57_FA57_FA57_FA57u64;
    let host = test_host(None);
    let key = test_workload_key();

    let mut default_decisions = HashMap::new();
    default_decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        default_config,
        &host,
        &default_decisions,
    )
    .expect("default-config calibration persists");

    let mut fast_decisions = HashMap::new();
    fast_decisions.insert(
        key.clone(),
        AutorouteDecision::new(
            ScanBackend::CpuFallback,
            8 * 1024 * 1024,
            1,
            13,
            Some(7),
            None,
        ),
    );
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        fast_config,
        &host,
        &fast_decisions,
    )
    .expect("fast-preset calibration persists");

    let default_loaded =
        load_autoroute_cache(&path, digest, test_rules_digest(), default_config, &host)
            .expect("default config still resolves after calibrating the fast preset");
    assert_eq!(
        default_loaded
            .get(&key)
            .and_then(AutorouteDecision::backend),
        Some(ScanBackend::SimdCpu),
        "calibrating the fast preset must not overwrite the default config's decision"
    );
    let fast_loaded = load_autoroute_cache(&path, digest, test_rules_digest(), fast_config, &host)
        .expect("fast preset resolves");
    assert_eq!(
        fast_loaded.get(&key).and_then(AutorouteDecision::backend),
        Some(ScanBackend::CpuFallback),
        "the fast preset keeps its own calibrated decision"
    );
}

#[test]
fn multi_config_cache_upserts_same_bucket_without_duplicating() {
    // Re-measuring the SAME (config, bucket) replaces the decision in place; the
    // merge must not append a duplicate (load rejects duplicate workload keys).
    let dir = tempfile::TempDir::new().expect("tempdir for upsert");
    let path = dir.path().join("upsert-autoroute-cache.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();

    let mut first = HashMap::new();
    first.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &first,
    )
    .unwrap();

    let mut second = HashMap::new();
    second.insert(
        key.clone(),
        AutorouteDecision::new(
            ScanBackend::CpuFallback,
            8 * 1024 * 1024,
            1,
            13,
            Some(7),
            None,
        ),
    );
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &second,
    )
    .unwrap();

    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect("re-measured cache reloads without a duplicate-key rejection");
    assert_eq!(
        loaded.len(),
        1,
        "re-measuring a bucket must upsert in place, not append a duplicate"
    );
    assert_eq!(
        loaded.get(&key).and_then(AutorouteDecision::backend),
        Some(ScanBackend::CpuFallback),
        "the newer measurement must win the upsert"
    );
}

#[test]
fn exact_tie_is_inconclusive_and_cannot_be_persisted() {
    let dir = tempfile::TempDir::new().expect("tempdir for tie calibration");
    let path = dir.path().join("tie-autoroute-cache.json");
    let digest = 0x0FF1_CE00_0FF1_CE00u64;
    let config_digest = 0xD1CE_D1CE_D1CE_D1CEu64;
    let host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();

    // SimdCpu and the GPU route measure identically (20ms). No timing evidence
    // proves either peer fastest, regardless of engagement overhead.
    let tie_to_simd =
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 20, None, Some(20));
    assert_eq!(
        tie_to_simd.resolved_routing_backend(),
        None,
        "an exact timing tie cannot prove one fastest route"
    );
    let mut decisions = HashMap::new();
    decisions.insert(key.clone(), tie_to_simd);
    let error = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect_err("an exact tie must not become a persisted autoroute decision")
    .to_string();
    assert!(
        error.contains("no confidence-supported one-shot route"),
        "proof rejection should name the missing separated winner, got {error:?}"
    );
}

#[test]
fn same_backend_tie_with_overlapping_peer_is_inconclusive() {
    let timing = |ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS);
    let decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::SimdCpu,
        8 * 1024 * 1024,
        1,
        test_measurement_shape_evidence(8 * 1024 * 1024, 1),
        7,
        1,
        route_timings(
            timing(10),
            Some(timing(10)),
            None,
            None,
            Some(timing(10)),
            Some(timing(10)),
            None,
            None,
        ),
        false,
        false,
    );

    assert_eq!(
        decision.resolved_routing_route(),
        None,
        "a same-backend tie cannot resolve while a peer backend also overlaps"
    );
    assert!(!decision.has_confidence_supported_route());
}

#[test]
fn separated_backend_uses_compiled_default_when_same_backend_plans_tie() {
    let timing = |ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS);
    let decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::CpuFallback,
        1,
        1,
        test_measurement_shape_evidence(1, 1),
        7,
        1,
        route_timings(
            timing(10_000),
            Some(timing(10)),
            None,
            None,
            Some(timing(10_000)),
            Some(timing(10)),
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
        }),
        "backend evidence may select the compiled default plan without inventing a nanosecond plan winner"
    );
    assert!(decision.has_confidence_supported_route());
}

#[test]
fn peer_separated_nondefault_tie_uses_stable_typed_plan() {
    let timing = |ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS);
    let mut timings = Vec::new();
    for backend in [ScanBackend::CpuFallback, ScanBackend::SimdCpu] {
        for phase2_plain_localizer in [false, true] {
            for phase2_keyword_localizer in [false, true] {
                let elapsed_ms = match backend {
                    ScanBackend::CpuFallback => 30,
                    ScanBackend::SimdCpu if phase2_plain_localizer => 10,
                    ScanBackend::SimdCpu => 100,
                    _ => unreachable!("fixture enumerates CPU and SIMD only"),
                };
                timings.push(RouteTimingEvidence::new(
                    MeasuredRoute {
                        backend,
                        phase2_plain_localizer,
                        phase2_keyword_localizer,
                    },
                    timing(elapsed_ms),
                ));
            }
        }
    }
    let decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::SimdCpu,
        1,
        1,
        test_measurement_shape_evidence(1, 1),
        7,
        1,
        timings,
        false,
        true,
    );

    assert_eq!(
        decision.resolved_routing_route(),
        Some(MeasuredRoute {
            backend: ScanBackend::SimdCpu,
            phase2_plain_localizer: true,
            phase2_keyword_localizer: false,
        }),
        "a tied nondefault leader must resolve deterministically without claiming an exact winner"
    );
    assert_eq!(
        decision.resolved_recovery_route(ScanBackend::SimdCpu, true),
        Some(MeasuredRoute {
            backend: ScanBackend::CpuFallback,
            phase2_plain_localizer: false,
            phase2_keyword_localizer: true,
        }),
        "a single remaining measured backend must retain its compiled default across a plan tie"
    );
}

#[test]
fn paired_backend_rounds_do_not_override_cross_backend_interval_overlap() {
    let host_drift = [
        10_000_000, 30_000_000, 12_000_000, 28_000_000, 14_000_000, 26_000_000, 16_000_000,
    ];
    let mut timings = Vec::new();
    for backend in [ScanBackend::CpuFallback, ScanBackend::SimdCpu] {
        for phase2_plain_localizer in [false, true] {
            for phase2_keyword_localizer in [false, true] {
                let trials = host_drift
                    .iter()
                    .map(|trial| {
                        trial
                            + if backend == ScanBackend::SimdCpu {
                                1_000_000
                            } else {
                                0
                            }
                    })
                    .collect::<Vec<_>>();
                timings.push(RouteTimingEvidence::new(
                    MeasuredRoute {
                        backend,
                        phase2_plain_localizer,
                        phase2_keyword_localizer,
                    },
                    BackendTimingEvidence::from_trial_ns(trials).expect("valid timing rounds"),
                ));
            }
        }
    }
    let decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::CpuFallback,
        1,
        1,
        test_measurement_shape_evidence(1, 1),
        7,
        1,
        timings,
        false,
        true,
    );

    assert_eq!(
        decision.resolved_routing_route(),
        None,
        "paired rounds must not replace the independent cross-backend confidence interval"
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
            Some(competitor),
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
        }),
        "paired rounds must prove a stable plan delta even when marginal intervals share host drift"
    );
}

#[test]
fn selected_margin_includes_the_next_same_backend_route() {
    let timing = |ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS);
    let decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::SimdCpu,
        8 * 1024 * 1024,
        1,
        test_measurement_shape_evidence(8 * 1024 * 1024, 1),
        7,
        1,
        route_timings(
            timing(10),
            Some(timing(30)),
            None,
            None,
            Some(timing(15)),
            Some(timing(40)),
            None,
            None,
        ),
        false,
        false,
    );

    assert_eq!(
        decision.resolved_routing_route(),
        Some(MeasuredRoute {
            backend: ScanBackend::SimdCpu,
            phase2_plain_localizer: false,
            phase2_keyword_localizer: false,
        })
    );
    assert_eq!(
        decision.selected_margin_ns(),
        Some(5_000_000),
        "the reported margin must measure the nearest complete route, not only another backend"
    );
}

#[test]
fn automatic_recovery_uses_the_fastest_remaining_measured_backend() {
    let decision = AutorouteDecision::new(
        ScanBackend::GpuWgpu,
        8 * 1024 * 1024,
        1,
        12,
        Some(20),
        Some(5),
    );
    let recovery = decision
        .resolved_recovery_route(ScanBackend::GpuWgpu, false)
        .expect("GPU winner has measured recovery peers");
    assert_eq!(recovery.backend, ScanBackend::SimdCpu);
    assert!(!recovery.phase2_plain_localizer);
    assert!(!recovery.phase2_keyword_localizer);

    let plan = automatic_recovery_plan(
        Some(&decision),
        ScanBackend::GpuWgpu,
        AutorouteRuntimeClass::OneShot,
    )
    .expect("recovery plan resolves")
    .expect("GPU route needs recovery plan");
    assert_eq!(plan.backend, ScanBackend::SimdCpu);

    let simd_decision =
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 5, Some(12), None);
    let simd_plan = automatic_recovery_plan(
        Some(&simd_decision),
        ScanBackend::SimdCpu,
        AutorouteRuntimeClass::OneShot,
    )
    .expect("SIMD recovery plan resolves")
    .expect("SIMD route needs a recovery plan");
    assert_eq!(simd_plan.backend, ScanBackend::CpuFallback);

    assert!(automatic_recovery_plan(
        Some(&simd_decision),
        ScanBackend::CpuFallback,
        AutorouteRuntimeClass::OneShot,
    )
    .expect("scalar route recovery policy resolves")
    .is_none());
}

#[test]
fn calibration_rejects_a_recovery_backend_crossover_inside_one_workload_class() {
    let mut decision = AutorouteDecision::new(
        ScanBackend::GpuWgpu,
        8 * 1024 * 1024,
        1,
        10,
        Some(20),
        Some(5),
    );
    let error = decision
        .merge_calibration_point(AutorouteDecision::new(
            ScanBackend::GpuWgpu,
            8 * 1024 * 1024 + 1,
            1,
            20,
            Some(10),
            Some(5),
        ))
        .expect_err("recovery crossover must split the workload class");
    assert!(error.contains("changes its confidence-supported remaining one-shot recovery route"));
}

#[test]
fn overlapping_confidence_produces_no_autoroute_decision() {
    let simd_timing = BackendTimingEvidence::from_trial_ns(vec![
        18_000_000, 20_000_000, 20_000_000, 20_000_000, 20_000_000, 20_000_000, 22_000_000,
    ])
    .expect("valid SIMD timing");
    // First GPU trial is the real cold dispatch (19 ms); the six warm trials
    // have an 18 ms median. Its one-shot representative is therefore 19 ms.
    let gpu_timing = BackendTimingEvidence::from_trial_ns(vec![
        19_000_000, 16_000_000, 18_000_000, 18_000_000, 18_000_000, 18_000_000, 22_000_000,
    ])
    .expect("valid GPU timing");
    let decision = AutorouteDecision::from_timing_evidence(
        ScanBackend::GpuWgpu,
        8 * 1024 * 1024,
        1,
        0xA11D_0B57_A11D_0B57,
        1,
        simd_timing,
        None,
        Some(gpu_timing),
    );

    assert!(
        !decision.has_confidence_supported_route(),
        "fixture must retain overlapping 95% confidence intervals"
    );
    assert_eq!(decision.simd_baseline_ms(), 20);
    assert_eq!(decision.gpu_ms(), Some(19));
    assert_eq!(
        decision.resolved_routing_backend(),
        None,
        "a lower measured median does not prove a fastest route when confidence overlaps"
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

#[test]
fn autoroute_cache_metadata_errors_are_not_reported_as_absence() {
    let dir = tempfile::TempDir::new().expect("metadata-error tempdir");
    let blocking_parent = dir.path().join("not-a-directory");
    std::fs::write(&blocking_parent, b"file blocks child metadata")
        .expect("write blocking parent fixture");
    let path = blocking_parent.join("autoroute.json");
    let host = test_host(None);

    let (loaded_path, decisions, cache_load_error) = load_persistent_autoroute_decisions(
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &host,
        Ok(Some(path.clone())),
    );
    assert_eq!(loaded_path, Some(path.clone()));
    assert!(decisions.is_empty());
    let error = cache_load_error.expect("metadata error must remain visible");
    assert!(
        error.contains("cannot inspect autoroute cache path")
            && error.contains(&path.display().to_string()),
        "metadata error must name the configured cache path: {error}"
    );
    assert!(
        !error.contains("No autoroute cache file exists"),
        "metadata failure must not be rendered as absence: {error}"
    );

    let inspection = inspect_autoroute_cache(Some(&path));
    assert!(!inspection.present);
    let inspection_error = inspection
        .error
        .expect("inspection must surface metadata failure");
    assert!(
        inspection_error.contains("cannot be inspected")
            && inspection_error.contains("Fix path permissions or parent storage"),
        "inspection metadata error: {inspection_error}"
    );
}

/// An outdated cache (older `version`, written before a field was added to the
/// schema) must be rejected on its schema version with a clear, actionable
/// message: NOT the opaque serde "missing field …" error a naive full
/// deserialize emits. Reproduces the real upgrade-path symptom: a stale on-disk
/// cache leaked `missing field decode_density_bucket` into every default scan
/// instead of a clean "unsupported autoroute cache version" verdict, because the
/// version gate sat after the full deserialize and could never run.
#[test]
fn autoroute_cache_rejects_outdated_schema_with_clear_version_error() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_outdated_{}.json",
        std::process::id()
    ));
    // A genuinely old cache: version 1, structurally incompatible with the
    // current schema (no `decode_density_bucket`, no `binary_version`, …).
    let outdated = br#"{
        "version": 1,
        "detector_digest": 123,
        "decisions": [
            [
                {"bytes_bucket": 1, "chunks_bucket": 1, "max_file_bucket": 1, "pattern_bucket": 13},
                "simd-regex"
            ]
        ]
    }"#;
    std::fs::write(&path, outdated).expect("write outdated cache");

    let host = test_host(None);
    let err = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0u64,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEFu64,
        &host,
    )
    .expect_err("outdated-schema cache must be rejected")
    .to_string();
    let _ = std::fs::remove_file(&path); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant

    assert!(
        err.contains("unsupported autoroute cache version"),
        "outdated cache must be rejected on its schema version, got: {err:?}"
    );
    assert!(
        !err.contains("missing field"),
        "version gate must fire BEFORE the full deserialize; a serde 'missing field' \
         error must not leak to the operator, got: {err:?}"
    );
}

#[test]
fn autoroute_cache_rejects_v25_decode_density_identity_before_payload_decode() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_v25_decode_density_{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        br#"{"version":25,"configs":[{"decisions":[[{"decode_density_bucket":3},{}]]}]}"#,
    )
    .expect("write v25 cache");

    let error = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
    )
    .expect_err("v25 decode-density identity must never be reused as current decoder work")
    .to_string();
    let _ = std::fs::remove_file(&path); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant

    assert!(
        error.contains("unsupported autoroute cache version 25")
            && error.contains(&format!("expects {AUTOROUTE_CACHE_VERSION}"))
            && error.contains("re-run calibration"),
        "v25 migration failure must be version-first and actionable: {error}"
    );
    assert!(
        !error.contains("missing field") && !error.contains("unknown field"),
        "v25 payload must not reach the current workload deserializer: {error}"
    );
}

#[test]
fn autoroute_cache_rejects_v28_before_phase1_identity_decode() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_v28_phase1_{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        br#"{"version":28,"configs":[{"decisions":[[{"bytes_bucket":23,"chunks_bucket":0,"max_file_bucket":23,"pattern_bucket":9,"decode_kind_mask":0,"decode_candidate_count_bucket":0,"decode_candidate_bytes_bucket":0,"decode_sample_bytes_bucket":0,"source_class_hash":1},{}]]}]}"#,
    )
    .expect("write v28 cache");

    let error = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
    )
    .expect_err("v28 identity must never be reused without phase-one admission classes")
    .to_string();
    let _ = std::fs::remove_file(&path); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant

    assert!(
        error.contains("unsupported autoroute cache version 28")
            && error.contains(&format!("expects {AUTOROUTE_CACHE_VERSION}"))
            && error.contains("re-run calibration"),
        "v28 migration failure must be version-first and actionable: {error}"
    );
    assert!(
        !error.contains("missing field") && !error.contains("unknown field"),
        "v28 payload must not reach the current phase-one identity deserializer: {error}"
    );
}

#[test]
fn autoroute_cache_rejects_v29_before_source_mixture_decode() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_v29_source_mixture_{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        br#"{"version":29,"configs":[{"decisions":[[{"source_class_hash":1},{}]]}]}"#,
    )
    .expect("write v29 cache");

    let error = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
    )
    .expect_err("v29 identity must never be reused without exact source mixtures")
    .to_string();
    let _ = std::fs::remove_file(&path); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant

    assert!(
        error.contains("unsupported autoroute cache version 29")
            && error.contains(&format!("expects {AUTOROUTE_CACHE_VERSION}"))
            && error.contains("re-run calibration"),
        "v29 migration failure must be version-first and actionable: {error}"
    );
    assert!(
        !error.contains("missing field") && !error.contains("unknown field"),
        "v29 payload must not reach the current source-mixture deserializer: {error}"
    );
}

#[test]
fn autoroute_cache_rejects_v30_before_workload_binding_decode() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_v30_workload_binding_{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        br#"{"version":30,"configs":[{"decisions":[[{"source_mixture":{"entries":[]}},{}]]}]}"#,
    )
    .expect("write v30 cache");

    let error = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
    )
    .expect_err("v30 decisions must never be reused without workload binding")
    .to_string();
    let _ = std::fs::remove_file(&path); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant

    assert!(
        error.contains("unsupported autoroute cache version 30")
            && error.contains(&format!("expects {AUTOROUTE_CACHE_VERSION}"))
            && error.contains("re-run calibration"),
        "v30 migration failure must be version-first and actionable: {error}"
    );
    assert!(
        !error.contains("missing field") && !error.contains("unknown field"),
        "v30 payload must not reach the current workload-binding deserializer: {error}"
    );
}

#[test]
fn autoroute_cache_save_reports_when_it_replaces_outdated_evidence() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_replace_outdated_{}.json",
        std::process::id()
    ));
    std::fs::write(&path, br#"{"version":1}"#).expect("write outdated cache");

    let mut decisions = HashMap::new();
    decisions.insert(
        test_workload_key(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    let outcome = save_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
        &decisions,
    )
    .expect("fresh calibration should replace outdated cache evidence");

    match outcome {
        AutorouteCacheSaveOutcome::Replaced { reason } => {
            assert!(
                reason.contains("version 1")
                    && reason.contains(&format!("expects {AUTOROUTE_CACHE_VERSION}")),
                "replacement disposition must explain both schema identities: {reason}"
            );
        }
        _ => panic!("outdated cache replacement must be operator-visible"),
    }
    std::fs::remove_file(&path).ok(); // LAW10: best-effort test cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_different_build_feature_set() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_feature_mismatch_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );

    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .unwrap();
    let mut cache: AutorouteCache =
        serde_json::from_slice(&std::fs::read(&path).expect("autoroute cache JSON"))
            .expect("cache should deserialize before tampering");
    cache
        .build_features
        .cli_features
        .push("__tampered_feature__".to_string());
    cache
        .build_features
        .scanner_features
        .push("__tampered_scanner_feature__".to_string());
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&cache).expect("tampered cache serializes"),
    )
    .expect("tampered cache writable");

    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("different build feature set must be rejected")
            .to_string()
            .contains("build feature set mismatch"),
        "autoroute cache must be tied to the compiled feature set"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_duplicate_workload_decisions() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_duplicate_workload_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );

    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .unwrap();
    let mut cache: AutorouteCache =
        serde_json::from_slice(&std::fs::read(&path).expect("autoroute cache JSON"))
            .expect("cache should deserialize before tampering");
    let config = cache
        .configs
        .first_mut()
        .expect("saved single-config cache has one config entry");
    let duplicate = config
        .decisions
        .first()
        .expect("saved cache contains one decision")
        .clone();
    config.decisions.push(duplicate);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&cache).expect("tampered cache serializes"),
    )
    .expect("tampered cache writable");

    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("duplicate workload decisions must be rejected")
            .to_string()
            .contains("duplicate autoroute workload decision"),
        "duplicate workload keys must not silently overwrite persisted route evidence"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
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

#[test]
fn autoroute_cache_rejects_empty_decision_set() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_empty_decisions_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );

    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .unwrap();
    let mut cache: AutorouteCache =
        serde_json::from_slice(&std::fs::read(&path).expect("autoroute cache JSON"))
            .expect("cache should deserialize before tampering");
    cache
        .configs
        .first_mut()
        .expect("saved single-config cache has one config entry")
        .decisions
        .clear();
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&cache).expect("tampered cache serializes"),
    )
    .expect("tampered cache writable");

    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("empty decision set must be rejected")
            .to_string()
            .contains("no workload decisions"),
        "a persisted autoroute cache with no measured workload decisions must not be accepted as calibrated"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_oversized_artifact_before_json_parse() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_oversized_cache_{}.json",
        std::process::id()
    ));
    let file = std::fs::File::create(&path).expect("create oversized autoroute cache fixture");
    file.set_len(AUTOROUTE_CACHE_FILE_BYTES + 1)
        .expect("sparse oversized autoroute cache fixture");
    drop(file);

    let loaded = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
    );
    let err = loaded
        .expect_err("oversized autoroute cache must be rejected before parse")
        .to_string();
    assert!(
        err.contains("autoroute cache exceeds") && err.contains("byte cap"),
        "oversized autoroute cache must fail with the cap oracle, got: {err}"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn measured_router_clears_dirty_after_successful_cache_save() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_dirty_clear_{}.json",
        std::process::id()
    ));
    let host = test_host(None);
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    let mut measured_this_run = HashSet::new();
    measured_this_run.insert(key.clone());
    let observer = Arc::new(Mutex::new(BTreeSet::new()));
    let mut router = MeasuredBackendRouter {
        pattern_count: 902,
        decode_workload_plan: test_decode_workload_plan(),
        detector_digest: 0x1234_5678_9ABC_DEF0,
        rules_digest: test_rules_digest().to_string(),
        config_digest: 0xA55A_D00D_CAFE_BEEF,
        gpu_participates: false,
        calibration_mode: true,
        host_profile: host,
        decisions,
        measured_this_run,
        runtime_faults: HashMap::new(),
        measurement_observer: Some(Arc::clone(&observer)),
        cache_path: Some(path.clone()),
        cache_load_error: None,
        cache_dirty: true,
        runtime_health: None,
        recovery_announced: false,
    };

    router
        .commit()
        .expect("dirty autoroute cache should commit after successful calibration");
    assert!(
        !router.cache_dirty,
        "successful autoroute cache save must clear the dirty bit so Drop does not rewrite it"
    );
    assert_eq!(
        observer
            .lock()
            .expect("observer lock")
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        vec![AutorouteMeasurementReceipt {
            config_digest: format!("{:016x}", router.config_digest),
            host_identity: host_identity_digest(&router.host_profile),
            workload: render_workload_key(&key),
            measurement_shape_digest: keyhog_core::hex_encode(
                &router.decisions[&key].calibration_points[0]
                    .measurement_shape
                    .shape_digest,
            ),
        }],
        "the receipt must carry the exact host, workload, and measurement shape that were persisted"
    );
    router
        .save_cache()
        .expect("clean autoroute cache save should be a no-op");

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn measured_router_drop_does_not_persist_dirty_cache() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_dirty_drop_{}.json",
        std::process::id()
    ));
    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired pre-state, recall-irrelevant
    let host = test_host(None);
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    let observer = Arc::new(Mutex::new(BTreeSet::new()));
    {
        let _router = MeasuredBackendRouter {
            pattern_count: 902,
            decode_workload_plan: test_decode_workload_plan(),
            detector_digest: 0x1234_5678_9ABC_DEF0,
            rules_digest: test_rules_digest().to_string(),
            config_digest: 0xA55A_D00D_CAFE_BEEF,
            gpu_participates: false,
            calibration_mode: true,
            host_profile: host,
            decisions,
            measured_this_run: [key].into_iter().collect(),
            runtime_faults: HashMap::new(),
            measurement_observer: Some(Arc::clone(&observer)),
            cache_path: Some(path.clone()),
            cache_load_error: None,
            cache_dirty: true,
            runtime_health: None,
            recovery_announced: false,
        };
    }

    assert!(
        !path.exists(),
        "autoroute must persist only from explicit successful calibration save, never from Drop"
    );
    assert!(
        observer.lock().expect("observer lock").is_empty(),
        "an unpersisted dirty route must not produce a measurement receipt"
    );
}

#[test]
fn measured_router_commit_discards_unmeasured_stale_decisions() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_stale_commit_{}.json",
        std::process::id()
    ));
    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired pre-state, recall-irrelevant
    let host = test_host(None);
    let measured_key = test_workload_key();
    let mut stale_key = measured_key.clone();
    stale_key.bytes_bucket = stale_key.bytes_bucket.saturating_add(1);
    let mut decisions = HashMap::new();
    decisions.insert(
        measured_key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    decisions.insert(
        stale_key.clone(),
        AutorouteDecision::new(
            ScanBackend::CpuFallback,
            8 * 1024 * 1024,
            1,
            13,
            Some(7),
            None,
        ),
    );
    let mut measured_this_run = HashSet::new();
    measured_this_run.insert(measured_key.clone());
    let mut router = MeasuredBackendRouter {
        pattern_count: 902,
        decode_workload_plan: test_decode_workload_plan(),
        detector_digest: 0x1234_5678_9ABC_DEF0,
        rules_digest: test_rules_digest().to_string(),
        config_digest: 0xA55A_D00D_CAFE_BEEF,
        gpu_participates: false,
        calibration_mode: true,
        host_profile: host.clone(),
        decisions,
        measured_this_run,
        runtime_faults: HashMap::new(),
        measurement_observer: None,
        cache_path: Some(path.clone()),
        cache_load_error: None,
        cache_dirty: true,
        runtime_health: None,
        recovery_announced: false,
    };

    router
        .commit()
        .expect("successful calibration commit should persist measured rows");
    let loaded = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &host,
    )
    .expect("committed autoroute cache should reload");
    assert!(
        loaded.contains_key(&measured_key),
        "measured calibration row must persist"
    );
    assert!(
        !loaded.contains_key(&stale_key),
        "calibration commit must not carry forward unmeasured stale cache rows"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn calibration_mode_remeasures_loaded_cache_decisions_before_reuse() {
    let host = test_host(None);
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(
            ScanBackend::CpuFallback,
            8 * 1024 * 1024,
            1,
            12,
            Some(8),
            None,
        ),
    );
    let mut router = MeasuredBackendRouter {
        pattern_count: 902,
        decode_workload_plan: test_decode_workload_plan(),
        detector_digest: 0x1234_5678_9ABC_DEF0,
        rules_digest: test_rules_digest().to_string(),
        config_digest: 0xA55A_D00D_CAFE_BEEF,
        gpu_participates: false,
        calibration_mode: true,
        host_profile: host,
        decisions,
        measured_this_run: HashSet::new(),
        runtime_faults: HashMap::new(),
        measurement_observer: None,
        cache_path: None,
        cache_load_error: None,
        cache_dirty: false,
        runtime_health: None,
        recovery_announced: false,
    };

    assert_eq!(
        router.reusable_decision_route(
            &key,
            Some(&test_measurement_shape_evidence(8 * 1024 * 1024, 1)),
        ),
        None,
        "calibration mode must not reuse a persisted cache row before this run remeasures the bucket"
    );
    router.measured_this_run.insert(key.clone());
    assert_eq!(
        router
            .reusable_decision_route(
                &key,
                Some(&test_measurement_shape_evidence(8 * 1024 * 1024, 1)),
            )
            .map(|route| route.backend),
        Some(ScanBackend::CpuFallback),
        "once the bucket is measured during this calibration run, duplicate batches may reuse the new in-memory decision"
    );
    assert_eq!(
        router.reusable_decision_route(
            &key,
            Some(&test_measurement_shape_evidence(12 * 1024 * 1024, 1)),
        ),
        None,
        "another exact size inside the same coarse class must be measured, not hidden behind the first point"
    );
}

#[test]
fn calibration_envelope_retains_agreeing_points_and_rejects_a_crossover() {
    let mut stable =
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 8, Some(12), None);
    stable
        .merge_calibration_point(AutorouteDecision::new(
            ScanBackend::SimdCpu,
            12 * 1024 * 1024,
            1,
            9,
            Some(13),
            None,
        ))
        .expect("agreeing points form one reproducible workload envelope");
    assert_eq!(stable.calibration_points.len(), 2);
    assert!(stable.contains_measurement(&test_measurement_shape_evidence(8 * 1024 * 1024, 1)));
    assert!(stable.contains_measurement(&test_measurement_shape_evidence(12 * 1024 * 1024, 1)));
    assert_eq!(
        stable.resolved_routing_backend(),
        Some(ScanBackend::SimdCpu)
    );

    let overlapping_simd = BackendTimingEvidence::from_trial_ns(vec![
        7_000_000, 8_000_000, 8_000_000, 8_000_000, 8_000_000, 8_000_000, 9_000_000,
    ])
    .expect("valid SIMD confidence fixture");
    let overlapping_cpu = BackendTimingEvidence::from_trial_ns(vec![
        1_000_000, 12_000_000, 12_000_000, 12_000_000, 12_000_000, 12_000_000, 20_000_000,
    ])
    .expect("valid CPU confidence fixture");
    let overlap_error = stable
        .merge_calibration_point(AutorouteDecision::from_timing_evidence(
            ScanBackend::SimdCpu,
            14 * 1024 * 1024,
            1,
            0xA11D_0B57_A11D_0B57,
            1,
            overlapping_simd,
            Some(overlapping_cpu),
            None,
        ))
        .expect_err("an inconclusive point cannot enter a routable workload class");
    assert!(
        overlap_error.contains("does not resolve one one-shot route"),
        "inconclusive point rejection must name the missing route proof: {overlap_error}"
    );

    let error = stable
        .merge_calibration_point(AutorouteDecision::new(
            ScanBackend::CpuFallback,
            16 * 1024 * 1024 - 1,
            1,
            20,
            Some(5),
            None,
        ))
        .expect_err("a measured winner change must split the workload identity");
    assert!(error.contains("changes its confidence-supported route across measured points"));
    assert!(error.contains("split the workload identity"));
}

#[test]
#[cfg(feature = "simd")]
fn cached_router_uses_visible_scalar_recovery_for_invalid_autoroute_state() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_cached_router_hit_miss_{}.json",
        std::process::id()
    ));
    let runtime_health_path = {
        let mut path = path.as_os_str().to_os_string();
        path.push(".runtime-health.json");
        std::path::PathBuf::from(path)
    };
    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired pre-state, recall-irrelevant
    std::fs::remove_file(&runtime_health_path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired pre-state, recall-irrelevant

    let scanner = CompiledScanner::compile_with_gpu_policy(
        phase1_test_detectors(),
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    )
    .expect("compile scanner");
    let caps = test_hw_caps();
    let runtime_status = scanner.runtime_status();
    let host = AutorouteHostProfile::from_caps(
        &caps,
        None,
        keyhog_scanner::hw_probe::gpu_backend_compiled(),
        test_scanner_eligible_backends(&scanner, None),
    )
    .with_live_hyperscan(scanner.simd_backend_available());
    let pattern_count = 902;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let hit_batch = vec![test_chunk_with_source(
        "token = abc\n".repeat(64),
        "filesystem",
    )];
    let hit_key = workload_key_with_plan(
        &hit_batch,
        pattern_count,
        scanner.phase1_admission_summary(&hit_batch),
        test_decode_workload_plan(),
    )
    .expect("hit workload classified");
    let miss_batch = vec![test_chunk_with_source(
        "token = abc\n".repeat(4096),
        "filesystem",
    )];
    let miss_key = workload_key_with_plan(
        &miss_batch,
        pattern_count,
        scanner.phase1_admission_summary(&miss_batch),
        test_decode_workload_plan(),
    )
    .expect("miss workload classified");
    assert_ne!(
        hit_key, miss_key,
        "test must exercise a real cache miss for a different workload bucket"
    );

    let mut decisions = HashMap::new();
    let hit_sample_bytes = hit_batch.iter().map(|chunk| chunk.data.len() as u64).sum();
    decisions.insert(
        hit_key.clone(),
        AutorouteDecision::new(
            if scanner.simd_backend_available() {
                ScanBackend::SimdCpu
            } else {
                ScanBackend::CpuFallback
            },
            hit_sample_bytes,
            hit_batch.len(),
            9,
            Some(12),
            None,
        ),
    );
    save_autoroute_cache(
        &path,
        runtime_status.detector_digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect("autoroute cache hit fixture should persist");

    let router = CachedBackendRouter::new(
        caps.clone(),
        pattern_count,
        test_rules_digest().to_string(),
        config_digest,
        true,
        Ok(Some(path.clone())),
        &scanner,
    );
    assert_eq!(
        router
            .choose_with_plan(&scanner, None, &hit_batch)
            .map(|selection| selection.backend)
            .expect("cache hit should choose persisted backend"),
        if scanner.simd_backend_available() {
            ScanBackend::SimdCpu
        } else {
            ScanBackend::CpuFallback
        }
    );
    let miss = router
        .choose_with_plan(&scanner, None, &miss_batch)
        .expect("cache miss must preserve scan coverage through visible recovery");
    assert_eq!(miss.backend, ScanBackend::CpuFallback);
    let miss_recovery = miss
        .autoroute_recovery
        .expect("cache miss must be marked as autoroute-state recovery");
    assert!(
        miss_recovery
            .reason
            .contains("autoroute calibration required")
            && miss_recovery
                .reason
                .contains("--autoroute-calibrate --autoroute-gpu")
            && miss_recovery.reason.contains("coverage:")
            && miss_recovery
                .reason
                .contains("complete through scalar correctness recovery"),
        "cache miss must preserve operator-visible autoroute diagnosis; got {}",
        miss_recovery.reason,
    );
    assert!(miss_recovery.announce, "first recovery must warn");
    assert_eq!(
        router
            .choose_with_plan(&scanner, Some(ScanBackend::CpuFallback), &miss_batch)
            .map(|selection| selection.backend)
            .expect("explicit backend diagnostics bypass autoroute cache"),
        ScanBackend::CpuFallback
    );

    let selected = router
        .choose_with_plan(&scanner, None, &hit_batch)
        .expect("persisted route before runtime fault");
    let recovery = keyhog_scanner::BackendRecoveryReceipt::new(
        selected.backend,
        ScanBackend::CpuFallback,
        vec![keyhog_scanner::RecoveredInputRange::new(
            0,
            0,
            hit_batch[0].data.len(),
        )],
        "injected dispatch fault".to_string(),
    );
    router
        .quarantine_recovered_route(&selected, &recovery)
        .expect("record exact route fault");
    assert!(router.autoroute_has_quarantined_routes());
    let quarantined = router
        .choose_with_plan(&scanner, None, &hit_batch)
        .expect("a quarantined route must recover visibly through the scalar oracle");
    assert_eq!(quarantined.backend, ScanBackend::CpuFallback);
    let quarantined = quarantined
        .autoroute_recovery
        .expect("quarantined route must carry recovery state")
        .reason;
    assert!(
        quarantined.contains("autoroute decision is quarantined")
            && quarantined.contains("will not silently substitute another route")
            && quarantined.contains("injected dispatch fault"),
        "quarantined route must fail visibly with recalibration guidance; got {quarantined}"
    );
    assert_eq!(
        router
            .choose_with_plan(&scanner, Some(ScanBackend::CpuFallback), &hit_batch)
            .expect("explicit diagnostic route bypasses quarantined autoroute evidence")
            .backend,
        ScanBackend::CpuFallback
    );

    let restarted_router = CachedBackendRouter::new(
        caps.clone(),
        pattern_count,
        test_rules_digest().to_string(),
        config_digest,
        true,
        Ok(Some(path.clone())),
        &scanner,
    );
    assert!(
        restarted_router.autoroute_has_quarantined_routes(),
        "daemon policy must expose a persisted quarantine after restart"
    );
    let after_restart = restarted_router
        .choose_with_plan(&scanner, None, &hit_batch)
        .expect("runtime quarantine must recover after process-local router reconstruction");
    assert_eq!(after_restart.backend, ScanBackend::CpuFallback);
    let after_restart = after_restart
        .autoroute_recovery
        .expect("restarted quarantined route must carry recovery state")
        .reason;
    assert!(
        after_restart.contains("autoroute decision is quarantined")
            && after_restart.contains("injected dispatch fault"),
        "durable route health must reject the exact persisted decision after restart; got {after_restart}"
    );
    let quarantined_inspection = inspect_autoroute_cache(Some(&path));
    assert_eq!(
        quarantined_inspection.readiness(),
        AutorouteReadiness::Quarantined
    );
    assert_eq!(quarantined_inspection.runtime_fault_count, 1);
    assert_eq!(
        quarantined_inspection.configs[0].quarantined_decision_count,
        1
    );
    assert!(quarantined_inspection.configs[0].decisions[0].runtime_quarantined);
    clear_runtime_route_faults(
        restarted_router
            .runtime_health
            .as_ref()
            .expect("cache-backed router has runtime-health identity"),
        [&hit_key],
    )
    .expect("successful recalibration clears the exact runtime fault");
    let repaired_inspection = inspect_autoroute_cache(Some(&path));
    assert_eq!(repaired_inspection.readiness(), AutorouteReadiness::Ready);
    assert_eq!(repaired_inspection.runtime_fault_count, 0);
    let repaired_router = CachedBackendRouter::new(
        caps,
        pattern_count,
        test_rules_digest().to_string(),
        config_digest,
        true,
        Ok(Some(path.clone())),
        &scanner,
    );
    assert_eq!(
        repaired_router
            .choose_with_plan(&scanner, None, &hit_batch)
            .expect("cleared runtime fault restores calibrated route")
            .backend,
        selected.backend
    );

    std::fs::write(&runtime_health_path, b"{not-json")
        .expect("write corrupt runtime-health fixture");
    let corrupt_health_router = CachedBackendRouter::new(
        test_hw_caps(),
        pattern_count,
        test_rules_digest().to_string(),
        config_digest,
        true,
        Ok(Some(path.clone())),
        &scanner,
    );
    let corrupt_health = corrupt_health_router
        .choose_with_plan(&scanner, None, &hit_batch)
        .expect("corrupt runtime health must recover with complete coverage");
    assert_eq!(corrupt_health.backend, ScanBackend::CpuFallback);
    let corrupt_health = corrupt_health
        .autoroute_recovery
        .expect("corrupt runtime health must be marked as recovery")
        .reason;
    assert!(
        corrupt_health.contains("cache or host identity was rejected")
            && corrupt_health.contains("runtime route-health artifact")
            && corrupt_health.contains("invalid JSON"),
        "corrupt runtime health must recover visibly with repair context; got {corrupt_health}"
    );
    assert_eq!(
        corrupt_health_router
            .choose_with_plan(&scanner, Some(ScanBackend::CpuFallback), &hit_batch)
            .expect("explicit diagnostic route bypasses corrupt autoroute health")
            .backend,
        ScanBackend::CpuFallback
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
    std::fs::remove_file(&runtime_health_path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_missing_cpu_model_identity() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_missing_cpu_model_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let mut host = test_host(None);
    host.cpu_model = None;
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );

    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    );
    assert!(
        saved
            .expect_err("missing CPU model must reject cache save")
            .to_string()
            .contains("CPU model string is unavailable"),
        "autoroute calibration must not persist without exact CPU identity"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_missing_core_topology_identity() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_missing_core_topology_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );

    let mut missing_cores = test_host(None);
    missing_cores.physical_cores = 0;
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &missing_cores,
        &decisions,
    );
    assert!(
        saved
            .expect_err("missing core count must reject cache save")
            .to_string()
            .contains("CPU core topology is unavailable"),
        "autoroute calibration must not persist without exact CPU core topology"
    );

    let mut impossible_topology = test_host(None);
    impossible_topology.physical_cores = 16;
    impossible_topology.logical_cores = 8;
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &impossible_topology,
        &decisions,
    );
    assert!(
        saved
            .expect_err("impossible core topology must reject cache save")
            .to_string()
            .contains("CPU core topology is unavailable"),
        "logical cores below physical cores cannot be trusted as a persistent host identity"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_missing_memory_identity() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_missing_memory_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );

    let mut missing_memory = test_host(None);
    missing_memory.total_memory_mb = None;
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &missing_memory,
        &decisions,
    );
    assert!(
        saved
            .expect_err("missing memory size must reject cache save")
            .to_string()
            .contains("system memory size is unavailable"),
        "autoroute calibration must not persist without exact RAM identity"
    );

    let mut zero_memory = test_host(None);
    zero_memory.total_memory_mb = Some(0);
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &zero_memory,
        &decisions,
    );
    assert!(
        saved
            .expect_err("zero memory size must reject cache save")
            .to_string()
            .contains("system memory size is unavailable"),
        "zero RAM is not a physically valid host identity for persisted calibration"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_missing_gpu_runtime_identity() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_missing_gpu_identity_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, Some(40)),
    );

    let mut missing_backend = test_host(Some("NVIDIA GeForce RTX 5090"));
    missing_backend.gpu_runtime_backend = None;
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &missing_backend,
        &decisions,
    );
    assert!(
        saved
            .expect_err("missing GPU runtime backend must reject cache save")
            .to_string()
            .contains("GPU runtime backend identity is unavailable"),
        "a GPU-capable autoroute profile must record which runtime backend was calibrated"
    );

    let mut missing_driver = test_host(Some("NVIDIA GeForce RTX 5090"));
    missing_driver.gpu_driver_runtime_identity = None;
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &missing_driver,
        &decisions,
    );
    assert!(
        saved
            .expect_err("missing GPU driver/runtime identity must reject cache save")
            .to_string()
            .contains("GPU driver/runtime identity is unavailable"),
        "a GPU-capable autoroute profile must record the driver/runtime identity used for timing"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_empty_or_impossible_gpu_runtime_identity() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_invalid_gpu_identity_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, Some(40)),
    );

    let mut whitespace_backend = test_host(Some("NVIDIA GeForce RTX 5090"));
    whitespace_backend.gpu_runtime_backend = Some("   ".to_string());
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &whitespace_backend,
        &decisions,
    );
    assert!(
        saved
            .expect_err("blank GPU runtime backend must reject cache save")
            .to_string()
            .contains("GPU runtime backend identity is unavailable"),
        "GPU runtime backend identity must not be whitespace"
    );

    let mut whitespace_driver = test_host(Some("NVIDIA GeForce RTX 5090"));
    whitespace_driver.gpu_driver_runtime_identity = Some("   ".to_string());
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &whitespace_driver,
        &decisions,
    );
    assert!(
        saved
            .expect_err("blank GPU driver/runtime identity must reject cache save")
            .to_string()
            .contains("GPU driver/runtime identity is unavailable"),
        "GPU driver/runtime identity must not be whitespace"
    );

    let mut whitespace_device = test_host(None);
    whitespace_device.gpu_name = Some("   ".to_string());
    whitespace_device.gpu_runtime_backend = Some("cuda".to_string());
    whitespace_device.gpu_driver_runtime_identity = Some("cuda:driver:535.00".to_string());
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &whitespace_device,
        &decisions,
    );
    assert!(
        saved
            .expect_err("blank GPU device identity must reject cache save")
            .to_string()
            .contains("GPU device identity is unavailable"),
        "GPU device identity must not be whitespace"
    );

    let mut runtime_without_device = test_host(None);
    runtime_without_device.gpu_runtime_backend = Some("cuda".to_string());
    runtime_without_device.gpu_driver_runtime_identity = Some("cuda:driver:535.00".to_string());
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &runtime_without_device,
        &decisions,
    );
    assert!(
        saved
            .expect_err("GPU runtime without GPU device identity must reject cache save")
            .to_string()
            .contains("GPU runtime backend is present without GPU device identity"),
        "autoroute must not persist impossible GPU runtime state"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_allows_software_gpu_without_runtime_identity() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_software_gpu_identity_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );

    let mut software_gpu_host = test_host(None);
    software_gpu_host.gpu_name = Some("llvmpipe (LLVM 15.0.7)".to_string());
    software_gpu_host.gpu_is_software = true;
    software_gpu_host.gpu_runtime_backend = None;
    software_gpu_host.gpu_driver_runtime_identity = None;

    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &software_gpu_host,
        &decisions,
    )
    .expect("software GPU names without a runtime must not block CPU/SIMD autoroute persistence");
    let loaded = load_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &software_gpu_host,
    )
    .expect("software GPU host profile should reload CPU/SIMD autoroute decisions");
    assert_eq!(
        loaded, decisions,
        "software renderer identity must remain part of the host profile without requiring GPU runtime identity"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_software_gpu_runtime_without_driver_identity() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_software_gpu_runtime_identity_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );

    let mut software_gpu_runtime = test_host(None);
    software_gpu_runtime.gpu_name = Some("llvmpipe (LLVM 15.0.7)".to_string());
    software_gpu_runtime.gpu_is_software = true;
    software_gpu_runtime.gpu_runtime_backend = Some("vulkan".to_string());
    software_gpu_runtime.gpu_driver_runtime_identity = None;
    let saved = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &software_gpu_runtime,
        &decisions,
    );
    assert!(
        saved
            .expect_err("explicit software GPU runtime must still require runtime identity")
            .to_string()
            .contains("GPU driver/runtime identity is unavailable"),
        "an explicit GPU runtime backend must not persist without exact driver/runtime identity"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_selected_backend_without_timing_evidence() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_missing_timing_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut bad = AutorouteDecision::new(
        ScanBackend::CpuFallback,
        8 * 1024 * 1024,
        1,
        12,
        Some(10),
        None,
    );
    // Drop the CpuFallback timing and its receipt so the selected backend has
    // no evidence while the remaining SIMD timing/receipt pair stays coherent.
    bad.primary_point_mut()
        .route_timings
        .retain(|entry| entry.backend != ScanBackend::CpuFallback.label());
    bad.primary_point_mut()
        .candidate_receipts
        .retain(|receipt| receipt.backend != ScanBackend::CpuFallback.label());
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        bad,
        "selected execution route is missing timing evidence",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("selected backend without evidence must be rejected")
            .to_string()
            .contains("selected execution route is missing timing evidence"),
        "selected backend timing evidence is part of the autoroute trust contract"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_missing_unselected_scalar_cpu_candidate() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_missing_unselected_cpu_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut bad =
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 10, Some(12), None);
    bad.primary_point_mut()
        .route_timings
        .retain(|entry| entry.backend != ScanBackend::CpuFallback.label());
    bad.primary_point_mut()
        .candidate_receipts
        .retain(|receipt| receipt.backend != ScanBackend::CpuFallback.label());
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
        bad,
        "timing set does not match eligible backend census",
    );

    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    let error = loaded.expect_err("every calibration must retain its scalar CPU peer");
    assert!(
        error
            .to_string()
            .contains("timing set does not match eligible backend census"),
        "unexpected validation error: {error}"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_missing_calibration_sample_evidence() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_missing_sample_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut bad = AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None);
    bad.primary_point_mut().sample_bytes = 0;
    bad.primary_point_mut().sample_chunks = 0;
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        bad,
        "missing calibration sample evidence",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("cache decision without calibration sample must be rejected")
            .to_string()
            .contains("missing calibration sample evidence"),
        "autoroute cache load must not trust a fastest-backend label without sample evidence"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_an_empty_calibration_envelope() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_empty_envelope_{}.json",
        std::process::id()
    ));
    let host = test_host(None);
    let mut bad = AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None);
    bad.calibration_points.clear();
    write_tampered_decision_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        0xA55A_D00D_CAFE_BEEF,
        &host,
        test_workload_key(),
        bad,
        "contains no measured calibration points",
    );
    let error = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &host,
    )
    .expect_err("an empty evidence envelope must never become a route")
    .to_string();
    assert!(error.contains("contains no measured calibration points"));
    std::fs::remove_file(&path).ok(); // LAW10: no runtime effect; test cleanup cannot affect production findings
}

#[test]
fn autoroute_cache_rejects_future_calibration_timestamps_everywhere() {
    let dir = tempfile::TempDir::new().expect("autoroute future-timestamp tempdir");
    let path = dir.path().join("autoroute.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut bad = AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None);
    bad.primary_point_mut().calibrated_at_unix_ms = u128::MAX;
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        bad,
        "in the future relative to the system clock",
    );

    let inspection = inspect_autoroute_cache(Some(&path));
    let inspection_error = inspection
        .error
        .as_deref()
        .expect("future evidence must make inspection unusable");
    assert!(
        inspection_error.contains("in the future relative to the system clock")
            && inspection_error.contains("correct the system clock")
            && inspection_error.contains("re-run calibration"),
        "inspection must explain the invalid clock evidence and its repair: {inspection_error}"
    );
    assert!(
        inspection.configs.is_empty(),
        "inspection cannot present any routes from a cache with future evidence"
    );

    let load_error = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect_err("future evidence must never reach route selection")
        .to_string();
    assert!(
        load_error.contains("in the future relative to the system clock")
            && load_error.contains("correct the system clock"),
        "scan-time load must fail closed with clock repair guidance: {load_error}"
    );
}

#[test]
fn autoroute_inspection_reports_exact_persisted_timestamp_and_derived_age() {
    let dir = tempfile::TempDir::new().expect("autoroute evidence-age tempdir");
    let path = dir.path().join("autoroute.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let decision = AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None);
    assert_eq!(decision.primary_point().calibrated_at_unix_ms, 1);
    let mut decisions = HashMap::new();
    decisions.insert(key.clone(), decision);
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect("valid historical evidence must remain accepted without an arbitrary expiry");
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect("age alone must not invalidate otherwise matching route evidence");
    assert_eq!(loaded[&key].primary_point().calibrated_at_unix_ms, 1);

    let inspection = inspect_autoroute_cache(Some(&path));
    assert_eq!(
        inspection.error, None,
        "valid old evidence remains inspectable"
    );
    let inspected_at = inspection
        .inspected_at_unix_ms
        .expect("inspection must disclose the age reference timestamp");
    let row = &inspection.configs[0].decisions[0];
    assert_eq!(row.calibrated_at_unix_ms, 1);
    assert_eq!(row.calibration_age_ms, inspected_at - 1);
}

#[test]
fn autoroute_cache_rejects_retired_backend_alias_labels() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_legacy_backend_alias_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();
    let mut bad = AutorouteDecision::new(
        ScanBackend::GpuWgpu,
        8 * 1024 * 1024,
        1,
        12,
        Some(20),
        Some(10),
    );
    bad.backend = ["gpu", "zero", "copy"].join("-");
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        bad,
        "unsupported backend decision",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("legacy backend aliases must not be accepted in persisted autoroute proof")
            .to_string()
            .contains("unsupported backend decision"),
        "autoroute cache must reject retired implementation aliases instead of canonicalizing them"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_zero_duration_timing_evidence() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_zero_duration_timing_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut bad = AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None);
    *route_timing_mut(bad.primary_point_mut(), ScanBackend::SimdCpu, false, false) =
        BackendTimingEvidence::constant_ms(0, AUTOROUTE_CALIBRATION_TRIALS);
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        bad,
        "invalid timing evidence for simd-regex plain_localizer=false keyword_localizer=false",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("zero-duration timing evidence must be rejected")
            .to_string()
            .contains("invalid timing evidence for simd-regex plain_localizer=false keyword_localizer=false"),
        "autoroute cache load must not trust physically impossible zero-duration timing evidence"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_noncanonical_trial_count_on_load_and_inspection() {
    let dir = tempfile::TempDir::new().expect("autoroute trial-count tempdir");
    let path = dir.path().join("autoroute.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut bad = AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None);
    bad.primary_point_mut().trials = AUTOROUTE_CALIBRATION_TRIALS + 1;
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        bad,
        "expected exactly 7",
    );

    let inspection = inspect_autoroute_cache(Some(&path));
    assert!(
        inspection
            .error
            .as_deref()
            .is_some_and(|error| error.contains("expected exactly 7")),
        "inspection must reject a noncanonical decision count: {inspection:?}"
    );
    let error = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect_err("load must reject a noncanonical decision count")
        .to_string();
    assert!(error.contains("expected exactly 7"), "load error: {error}");
}

#[test]
fn autoroute_cache_rejects_extra_backend_trials_on_load_and_inspection() {
    let dir = tempfile::TempDir::new().expect("autoroute extra-trials tempdir");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();
    let base = AutorouteDecision::new(
        ScanBackend::SimdCpu,
        8 * 1024 * 1024,
        1,
        12,
        Some(20),
        Some(30),
    );
    let mut simd = base.clone();
    route_timing_mut(simd.primary_point_mut(), ScanBackend::SimdCpu, false, false)
        .trials_ns
        .push(10_000_000);
    let mut cpu = base.clone();
    route_timing_mut(
        cpu.primary_point_mut(),
        ScanBackend::CpuFallback,
        false,
        false,
    )
    .trials_ns
    .push(20_000_000);
    let mut gpu = base;
    route_timing_mut(gpu.primary_point_mut(), ScanBackend::GpuWgpu, false, false)
        .trials_ns
        .push(30_000_000);

    for (label, bad, expected_error) in [
        ("simd", simd, "invalid timing evidence for simd-regex"),
        ("cpu", cpu, "invalid timing evidence for cpu-fallback"),
        (
            "gpu",
            gpu,
            "invalid timing evidence for gpu-wgpu-region-presence",
        ),
    ] {
        let path = dir.path().join(format!("{label}.json"));
        write_tampered_decision_cache(
            &path,
            digest,
            config_digest,
            &host,
            key.clone(),
            bad,
            expected_error,
        );
        let inspection = inspect_autoroute_cache(Some(&path));
        assert!(
            inspection
                .error
                .as_deref()
                .is_some_and(|error| error.contains(expected_error)),
            "inspection must reject extra {label} trials: {inspection:?}"
        );
        let error = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
            .expect_err("load must reject extra backend trials")
            .to_string();
        assert!(error.contains(expected_error), "load error: {error}");
    }
}

#[test]
fn autoroute_cache_rejects_non_primary_timing_summary_fields() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_fabricated_timing_summary_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect("valid primary timing evidence must save");
    let mut cache_json: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&path).expect("tampered cache fixture must be readable"),
    )
    .expect("tampered cache fixture must be JSON");
    cache_json["configs"][0]["decisions"][0]["decision"]["calibration_points"][0]
        ["route_timings"][0]["timing"]["mean_ns"] = serde_json::json!(1);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&cache_json).expect("tampered cache JSON must serialize"),
    )
    .expect("tampered cache fixture must be writable");
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("non-primary timing summary fields must be rejected")
            .to_string()
            .contains("unknown field `mean_ns`"),
        "autoroute cache load must reject summary fields instead of trusting persisted duplicates"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_unknown_and_incomplete_proof_fields() {
    let dir = tempfile::tempdir().expect("autoroute strict-schema tempdir");
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
    .expect("valid strict-schema fixture");
    let canonical: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&path).expect("strict-schema fixture must be readable"),
    )
    .expect("strict-schema fixture must be JSON");

    for (label, mut tampered) in [
        ("cache", canonical.clone()),
        ("features", canonical.clone()),
        ("host", canonical.clone()),
        ("config", canonical.clone()),
        ("workload", canonical.clone()),
        ("decision", canonical.clone()),
    ] {
        let target = match label {
            "cache" => &mut tampered,
            "features" => &mut tampered["build_features"],
            "host" => &mut tampered["configs"][0]["host"],
            "config" => &mut tampered["configs"][0],
            "workload" => &mut tampered["configs"][0]["decisions"][0]["workload"],
            "decision" => &mut tampered["configs"][0]["decisions"][0]["decision"],
            _ => unreachable!("fixed strict-schema case"),
        };
        target["unexpected_proof_field"] = serde_json::json!(true);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&tampered).expect("tampered schema JSON"),
        )
        .expect("write tampered strict-schema fixture");
        let error = load_autoroute_cache(
            &path,
            detector_digest,
            test_rules_digest(),
            config_digest,
            &host,
        )
        .expect_err("unknown proof field must fail closed")
        .to_string();
        assert!(
            error.contains("unknown field `unexpected_proof_field`"),
            "{label} unknown field error: {error}"
        );
        assert!(
            inspect_autoroute_cache(Some(&path)).error.is_some(),
            "inspection must reject unknown {label} proof fields"
        );
    }

    for field in [
        "cli_features",
        "scanner_features",
        "sources_features",
        "verifier_features",
    ] {
        let mut tampered = canonical.clone();
        tampered["build_features"]
            .as_object_mut()
            .expect("build features object")
            .remove(field);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&tampered).expect("incomplete schema JSON"),
        )
        .expect("write incomplete strict-schema fixture");
        let error = load_autoroute_cache(
            &path,
            detector_digest,
            test_rules_digest(),
            config_digest,
            &host,
        )
        .expect_err("missing build feature vector must fail closed")
        .to_string();
        assert!(
            error.contains(&format!("missing field `{field}`")),
            "missing {field} error: {error}"
        );
    }
}

#[test]
fn backend_timing_evidence_rejects_empty_trial_sets_at_construction() {
    assert!(
        super::evidence::BackendTimingEvidence::from_trial_ns(Vec::new()).is_none(),
        "autoroute timing evidence must not convert an empty trial set into a zero-duration route"
    );
}

#[test]
fn immutable_gpu_preparation_costs_change_only_the_cold_trial() {
    let literal_preparation_ns = 60;
    let phase2_preparation_ns = 30;
    let evidence =
        super::evidence::BackendTimingEvidence::from_trial_ns(vec![10, 20, 20, 20, 20, 20, 20])
            .expect("timing evidence")
            .add_to_first_trial(literal_preparation_ns + phase2_preparation_ns);
    assert_eq!(evidence.trials_ns, vec![100, 20, 20, 20, 20, 20, 20]);
    let (cold_ns, warm, one_shot_ns) =
        super::evidence::gpu_cold_warm_route_evidence(&evidence).expect("cold/warm split");
    assert_eq!(cold_ns, 100);
    assert_eq!(warm.median_ns(), 20);
    assert_eq!(one_shot_ns, 100);
}

#[test]
fn calibration_candidate_order_rotates_across_workload_bands() {
    let rotations = [1_u64, 2, 4, 8, 16, 32]
        .into_iter()
        .map(|bytes| super::calibration::calibration_candidate_rotation(bytes, 1, 4))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(rotations, [0, 1, 2, 3].into_iter().collect());
}

#[test]
fn autoroute_confidence_uses_student_t_for_small_calibration_samples() {
    let simd_timing = super::evidence::BackendTimingEvidence::from_trial_ns(vec![
        90, 95, 100, 100, 100, 105, 110,
    ])
    .expect("SIMD timing evidence");
    let cpu_timing = super::evidence::BackendTimingEvidence::from_trial_ns(vec![
        101, 106, 111, 111, 111, 116, 121,
    ])
    .expect("CPU timing evidence");
    let decision = AutorouteDecision::from_timing_evidence(
        ScanBackend::SimdCpu,
        8 * 1024 * 1024,
        1,
        0xA11D_0B57_A11D_0B57,
        1,
        simd_timing,
        Some(cpu_timing),
        None,
    );

    assert!(
        !decision.selected_backend_has_non_overlapping_confidence(ScanBackend::SimdCpu),
        "n=7 calibration samples must use the wider Student-t interval; the old normal 1.96 \
         multiplier made these adjacent timing distributions look falsely separated"
    );
}

#[test]
fn scalar_reference_inconsistency_aborts_calibration_contract() {
    let reference = vec![vec![canonical_test_match(
        "detector-reference",
        7,
        Some("src/reference.rs"),
        Some(4),
        19,
    )]];
    let reference_key = canonical_matches(&reference);
    assert!(calibration::calibration_candidate_parity_result(
        ScanBackend::CpuFallback,
        1,
        &reference,
        &reference_key,
    )
    .is_ok());

    let mut divergent = reference.clone();
    divergent[0][0].location.offset += 1;
    let error = calibration::calibration_candidate_parity_result(
        ScanBackend::CpuFallback,
        2,
        &divergent,
        &reference_key,
    )
    .expect_err("a divergent scalar trial must abort reference calibration")
    .to_string();
    assert!(
        error.contains("reference backend produced inconsistent findings")
            && error.contains("no backend decision was persisted"),
        "reference inconsistency must be an autoroute calibration failure, got: {error}"
    );
}

#[test]
fn injected_simd_miss_rejects_only_simd_and_preserves_scalar_oracle() {
    let reference = vec![vec![canonical_test_match(
        "detector-simd-miss",
        5,
        Some("src/simd-miss.rs"),
        Some(3),
        11,
    )]];
    let reference_key = canonical_matches(&reference);
    assert!(calibration::calibration_candidate_parity_result(
        ScanBackend::CpuFallback,
        1,
        &reference,
        &reference_key,
    )
    .is_ok());

    let simd_miss = vec![Vec::new()];
    let error = calibration::calibration_candidate_parity_result(
        ScanBackend::SimdCpu,
        1,
        &simd_miss,
        &reference_key,
    )
    .expect_err("a SIMD-only miss must reject the SIMD candidate")
    .to_string();
    assert!(error.contains("rejected eligible backend simd"), "{error}");
    assert!(
        !error.contains("reference backend produced inconsistent findings"),
        "an optional SIMD miss must not invalidate the scalar oracle: {error}"
    );
}

#[test]
fn autoroute_reference_mismatch_evidence_names_fields_without_values() {
    let reference_match = keyhog_core::RawMatch {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS Access Key".into(),
        service: "aws".into(),
        severity: keyhog_core::Severity::High,
        credential: "AKIAIOSFODNN7EXAMPLE".into(),
        credential_hash: [0xAB; 32].into(),
        companions: std::collections::HashMap::from([(
            "account".to_string(),
            "production@example.test".to_string(),
        )]),
        location: keyhog_core::MatchLocation {
            source: "filesystem".into(),
            file_path: Some("src/secrets.rs".into()),
            line: Some(42),
            offset: 1337,
            commit: Some("commit-sensitive-a".into()),
            author: Some("author-a@example.test".into()),
            date: Some("2026-07-14T00:00:00Z".into()),
        },
        entropy: Some(4.2),
        confidence: Some(0.99),
    };
    let mut trial_match = reference_match.clone();
    trial_match.credential = "AKIAZZZZZZZZZZZZZZZZ".into();
    trial_match.credential_hash = [0xCD; 32].into();
    trial_match
        .companions
        .insert("account".to_string(), "staging@example.test".to_string());
    trial_match.location.commit = Some("commit-sensitive-b".into());
    trial_match.location.author = Some("author-b@example.test".into());
    trial_match.location.date = Some("2026-07-15T00:00:00Z".into());

    let fields = calibration::calibration_mismatch_field_names(
        &[vec![reference_match]],
        &[vec![trial_match]],
    );

    assert_eq!(
        fields,
        vec![
            "author",
            "commit",
            "companions",
            "credential_hash",
            "credential_value",
            "date",
        ]
    );
    let rendered = format!("{fields:?}");
    for sensitive in [
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAZZZZZZZZZZZZZZZZ",
        "production@example.test",
        "staging@example.test",
        "author-a@example.test",
        "author-b@example.test",
        "commit-sensitive-a",
        "commit-sensitive-b",
    ] {
        assert!(!rendered.contains(sensitive));
    }
}

fn canonical_test_match(
    detector_id: &str,
    hash_byte: u8,
    file_path: Option<&str>,
    line: Option<usize>,
    offset: usize,
) -> keyhog_core::RawMatch {
    keyhog_core::RawMatch {
        detector_id: detector_id.into(),
        detector_name: detector_id.into(),
        service: "test".into(),
        severity: keyhog_core::Severity::High,
        credential: format!("{detector_id}-{offset}").into(),
        credential_hash: [hash_byte; 32].into(),
        companions: std::collections::HashMap::new(),
        location: keyhog_core::MatchLocation {
            source: "filesystem".into(),
            file_path: file_path.map(Into::into),
            line,
            offset,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.2),
        confidence: Some(0.99),
    }
}

fn assert_canonical_reference_parity(
    reference: &[Vec<keyhog_core::RawMatch>],
    trial: &[Vec<keyhog_core::RawMatch>],
) {
    let reference_key = canonical_matches(reference);
    assert_eq!(
        canonical_matches_equal_reference(trial, &reference_key),
        canonical_matches(trial) == reference_key,
        "borrowed autoroute parity check must match canonical sorted-vector equality"
    );
}

#[test]
fn canonical_matches_equal_reference_preserves_duplicate_multiset_semantics() {
    let a = canonical_test_match("detector-a", 0xA1, Some("src/a.rs"), Some(10), 100);
    let duplicate_a = a.clone();
    let b = canonical_test_match("detector-b", 0xB2, Some("src/b.rs"), Some(20), 200);
    let wrong_line = canonical_test_match("detector-a", 0xA1, Some("src/a.rs"), Some(11), 100);
    let reference = vec![vec![a.clone(), duplicate_a.clone(), b.clone()]];

    assert_canonical_reference_parity(&[], &[]);
    assert!(canonical_matches_equal_reference(
        &[],
        &canonical_matches(&[])
    ));
    assert_canonical_reference_parity(
        &reference,
        &[vec![b.clone(), duplicate_a.clone(), a.clone()]],
    );
    assert!(canonical_matches_equal_reference(
        &[vec![b.clone(), duplicate_a.clone(), a.clone()]],
        &canonical_matches(&reference)
    ));
    assert_canonical_reference_parity(&reference, &[vec![a.clone(), b.clone()]]);
    assert!(!canonical_matches_equal_reference(
        &[vec![a.clone(), b.clone()]],
        &canonical_matches(&reference)
    ));
    assert_canonical_reference_parity(
        &reference,
        &[vec![a.clone(), duplicate_a.clone(), b.clone(), b.clone()]],
    );
    assert!(!canonical_matches_equal_reference(
        &[vec![a.clone(), duplicate_a.clone(), b.clone(), b.clone()]],
        &canonical_matches(&reference)
    ));
    assert_canonical_reference_parity(
        &reference,
        &[vec![wrong_line, duplicate_a.clone(), b.clone()]],
    );
    assert!(!canonical_matches_equal_reference(
        &[vec![a.clone()], vec![duplicate_a, b]],
        &canonical_matches(&reference)
    ));
}

#[test]
fn canonical_match_parity_covers_every_user_visible_raw_match_field() {
    let base = canonical_test_match("detector-a", 0xA1, Some("src/a.rs"), Some(10), 100);
    let reference = vec![vec![base.clone()]];
    let reference_key = canonical_matches(&reference);
    let mut variants = Vec::new();

    let mut changed = base.clone();
    changed.detector_id = "detector-b".into();
    variants.push(("detector id", changed));
    let mut changed = base.clone();
    changed.detector_name = "Changed name".into();
    variants.push(("detector name", changed));
    let mut changed = base.clone();
    changed.service = "changed-service".into();
    variants.push(("service", changed));
    let mut changed = base.clone();
    changed.severity = keyhog_core::Severity::Critical;
    variants.push(("severity", changed));
    let mut changed = base.clone();
    changed.credential = "changed-secret".into();
    variants.push(("credential value", changed));
    let mut changed = base.clone();
    changed.credential_hash = [0xCC; 32].into();
    variants.push(("stored credential hash", changed));
    let mut changed = base.clone();
    changed
        .companions
        .insert("account".to_string(), "sensitive-companion".to_string());
    variants.push(("companions", changed));
    let mut changed = base.clone();
    changed.location.source = "git".into();
    variants.push(("source", changed));
    let mut changed = base.clone();
    changed.location.file_path = Some("src/b.rs".into());
    variants.push(("file path", changed));
    let mut changed = base.clone();
    changed.location.line = Some(11);
    variants.push(("line", changed));
    let mut changed = base.clone();
    changed.location.offset = 101;
    variants.push(("offset", changed));
    let mut changed = base.clone();
    changed.location.commit = Some("deadbeef".into());
    variants.push(("commit", changed));
    let mut changed = base.clone();
    changed.location.author = Some("author@example.test".into());
    variants.push(("author", changed));
    let mut changed = base.clone();
    changed.location.date = Some("2026-07-13T00:00:00Z".into());
    variants.push(("date", changed));
    let mut changed = base.clone();
    changed.entropy = Some(4.3);
    variants.push(("entropy", changed));
    let mut changed = base.clone();
    changed.confidence = Some(0.98);
    variants.push(("confidence", changed));

    for (field, changed) in variants {
        let trial = vec![vec![changed]];
        assert_canonical_reference_parity(&reference, &trial);
        assert!(
            !canonical_matches_equal_reference(&trial, &reference_key),
            "autoroute parity must reject a backend that changes {field}"
        );
    }

    let shifted_chunk = vec![Vec::new(), vec![base]];
    assert_canonical_reference_parity(&reference, &shifted_chunk);
    assert!(
        !canonical_matches_equal_reference(&shifted_chunk, &reference_key),
        "autoroute parity must retain chunk identity"
    );
}

#[test]
fn canonical_match_parity_large_path_preserves_full_multiset() {
    let reference_matches: Vec<_> = (0..257)
        .map(|offset| {
            canonical_test_match(
                "detector-large",
                (offset % 251) as u8,
                Some("src/large.rs"),
                Some(offset + 1),
                offset,
            )
        })
        .collect();
    let reference = vec![reference_matches.clone()];
    let reference_key = canonical_matches(&reference);
    let mut reordered = reference_matches;
    reordered.reverse();
    assert!(canonical_matches_equal_reference(
        &[reordered.clone()],
        &reference_key
    ));

    reordered[128].service = "divergent-service".into();
    assert!(
        !canonical_matches_equal_reference(&[reordered], &reference_key),
        "the allocation-backed >256 path must compare full match semantics"
    );
}

#[test]
fn autoroute_candidate_rejection_aborts_calibration_contract() {
    let reference = vec![vec![canonical_test_match(
        "detector-candidate",
        9,
        Some("src/candidate.rs"),
        Some(8),
        33,
    )]];
    let reference_key = canonical_matches(&reference);
    let mut divergent = reference.clone();
    divergent[0][0].service = "divergent-service".into();
    let error = calibration::calibration_candidate_parity_result(
        ScanBackend::GpuWgpu,
        1,
        &divergent,
        &reference_key,
    )
    .expect_err("an eligible backend with divergent findings must be rejected")
    .to_string();
    assert!(
        error.contains("rejected eligible backend gpu")
            && error.contains("cannot prove fastest-correct routing")
            && error.contains("no routing decision was persisted"),
        "eligible candidate rejection must be an autoroute calibration failure, got: {error}"
    );
}

#[test]
fn autoroute_cache_rejects_missing_correctness_digest() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_missing_correctness_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut bad = AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None);
    bad.primary_point_mut().candidate_receipts[0].correctness_digest = 0;
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        bad,
        "missing correctness digest",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("cache decision without correctness digest must be rejected")
            .to_string()
            .contains("missing correctness digest"),
        "autoroute cache load must not trust timing evidence without parity evidence"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_binds_every_timing_row_to_one_parity_receipt() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_candidate_receipts_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();

    let mut missing = AutorouteDecision::new(
        ScanBackend::CpuFallback,
        8 * 1024 * 1024,
        1,
        12,
        Some(7),
        None,
    );
    missing.primary_point_mut().candidate_receipts.pop();
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        missing,
        "receipt set does not match eligible backend census",
    );

    let mut divergent = AutorouteDecision::new(
        ScanBackend::CpuFallback,
        8 * 1024 * 1024,
        1,
        12,
        Some(7),
        None,
    );
    divergent.primary_point_mut().candidate_receipts[1].correctness_digest ^= 1;
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        divergent,
        "does not match the reference correctness digest",
    );

    let mut timing_mutation = AutorouteDecision::new(
        ScanBackend::CpuFallback,
        8 * 1024 * 1024,
        1,
        12,
        Some(7),
        None,
    );
    route_timing_mut(
        timing_mutation.primary_point_mut(),
        ScanBackend::CpuFallback,
        false,
        false,
    )
    .trials_ns[0] += 1;
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        timing_mutation,
        "does not match its timing evidence",
    );

    let mut reordered_timings = AutorouteDecision::new(
        ScanBackend::CpuFallback,
        8 * 1024 * 1024,
        1,
        12,
        Some(7),
        None,
    );
    reordered_timings
        .primary_point_mut()
        .route_timings
        .swap(0, 1);
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        reordered_timings,
        "route timings are not in canonical backend/plain/keyword order",
    );

    let mut reordered_receipts = AutorouteDecision::new(
        ScanBackend::CpuFallback,
        8 * 1024 * 1024,
        1,
        12,
        Some(7),
        None,
    );
    reordered_receipts
        .primary_point_mut()
        .candidate_receipts
        .swap(0, 1);
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        reordered_receipts,
        "candidate receipts are not in canonical backend/plain/keyword order",
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_binds_gpu_timings_and_receipts_to_one_acquired_peer() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_gpu_peer_identity_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();

    let mut missing = AutorouteDecision::new(
        ScanBackend::GpuWgpu,
        8 * 1024 * 1024,
        1,
        12,
        Some(20),
        Some(7),
    );
    missing
        .primary_point_mut()
        .route_timings
        .iter_mut()
        .find(|entry| {
            entry.backend == ScanBackend::GpuWgpu.label()
                && !entry.phase2_plain_localizer
                && !entry.phase2_keyword_localizer
        })
        .expect("GPU baseline timing")
        .peer_identity = None;
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        missing,
        "must bind exactly one acquired GPU peer identity",
    );

    let mut mismatched = AutorouteDecision::new(
        ScanBackend::GpuWgpu,
        8 * 1024 * 1024,
        1,
        12,
        Some(20),
        Some(7),
    );
    let receipt = mismatched
        .primary_point_mut()
        .candidate_receipts
        .iter_mut()
        .find(|receipt| {
            receipt.backend == ScanBackend::GpuWgpu.label()
                && !receipt.phase2_plain_localizer
                && !receipt.phase2_keyword_localizer
        })
        .expect("GPU baseline parity receipt");
    receipt.peer_identity = Some("different-acquired-peer".to_string());
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
        mismatched,
        "is not bound to its timing peer identity",
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_requires_every_live_gpu_candidate_timing_and_receipt() {
    let dir = tempfile::tempdir().expect("autoroute GPU candidate census tempdir");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let mut host = test_host(Some("NVIDIA GeForce RTX 5090"));
    host.eligible_backends = test_eligible_backends(Some(ScanBackend::GpuWgpu));
    host.eligible_backends
        .push(ScanBackend::GpuCuda.label().to_string());
    host.eligible_backends.sort_unstable();
    let key = test_workload_key();
    let complete = valid_decision_for_host(&host);

    for backend in [ScanBackend::GpuCuda, ScanBackend::GpuWgpu] {
        let mut missing = complete.clone();
        missing
            .primary_point_mut()
            .route_timings
            .retain(|entry| entry.backend != backend.label());
        missing
            .primary_point_mut()
            .candidate_receipts
            .retain(|receipt| receipt.backend != backend.label());
        let path = dir.path().join(format!("{}.json", backend.label()));
        write_tampered_decision_cache(
            &path,
            digest,
            config_digest,
            &host,
            key.clone(),
            missing,
            "timing set does not match eligible backend census",
        );
        let error = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
            .expect_err("deleting an eligible GPU peer's evidence must invalidate replay")
            .to_string();
        assert!(
            error.contains("timing set does not match eligible backend census"),
            "{backend:?} replay error: {error}"
        );
    }
}

#[test]
fn autoroute_cache_rejects_coordinated_candidate_and_evidence_deletion() {
    let dir = tempfile::tempdir().expect("autoroute coordinated deletion tempdir");
    let path = dir.path().join("autoroute.json");
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let live_host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();
    let decisions = HashMap::from([(key, valid_decision_for_host(&live_host))]);
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &live_host,
        &decisions,
    )
    .expect("complete GPU candidate evidence saves");

    let mut cache: AutorouteCache = serde_json::from_slice(
        &std::fs::read(&path).expect("coordinated-deletion cache is readable"),
    )
    .expect("coordinated-deletion cache is JSON");
    let config = &mut cache.configs[0];
    config.host = test_host(None);
    config.decisions[0].decision = valid_decision_for_host(&config.host);
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&cache).expect("coordinated-deletion cache serializes"),
    )
    .expect("coordinated-deletion cache is writable");

    let error = load_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &live_host,
    )
    .expect_err("a cache cannot delete the live GPU census together with its evidence")
    .to_string();
    assert!(
        error.contains("host profile mismatch"),
        "load error: {error}"
    );
}

#[test]
fn autoroute_host_rejects_noncanonical_candidate_census() {
    let cpu = ScanBackend::CpuFallback.label().to_string();
    let simd = ScanBackend::SimdCpu.label().to_string();
    for (label, census, expected) in [
        ("empty", vec![], "census is unavailable"),
        (
            "duplicate",
            vec![cpu.clone(), cpu.clone(), simd.clone()],
            "not unique canonical order",
        ),
        (
            "unsorted",
            vec![simd.clone(), cpu.clone()],
            "not unique canonical order",
        ),
        (
            "unknown",
            vec![cpu.clone(), "gpu-mystery".to_string(), simd.clone()],
            "unsupported backend",
        ),
    ] {
        let mut host = test_host(None);
        host.eligible_backends = census;
        let error = host
            .require_exact_identity()
            .expect_err("invalid candidate census must fail closed");
        assert!(
            error.contains(expected),
            "{label} census error {error:?} did not contain {expected:?}"
        );
    }
}

#[test]
fn derived_accessors_match_the_persisted_timing_evidence() {
    // v21 REPLACES the old "reject a cache whose STORED cold/warm fields mismatch
    // the timing" contract: those denormalized fields are gone, so the derived
    // values are computed from the timing on demand and CANNOT disagree with it.
    // This proves that ONE-PLACE invariant directly, every accessor reflects the
    // persisted timing evidence exactly, with no second copy that could drift.
    let decision = AutorouteDecision::new(
        ScanBackend::GpuWgpu,
        8 * 1024 * 1024,
        1,
        12,
        Some(9),
        Some(20),
    );

    // Per-backend ms derives from the (constant) timing built for each input.
    assert_eq!(decision.simd_baseline_ms(), 12);
    assert_eq!(decision.cpu_baseline_ms(), Some(9));
    assert_eq!(decision.gpu_ms(), Some(20));

    // GPU cold / warm / route derive from the driver timing through the single owner
    // `gpu_cold_warm_route_evidence`, so the accessors equal a fresh derivation.
    let gpu_timing = decision
        .primary_point()
        .baseline_timing_for_backend(ScanBackend::GpuWgpu)
        .expect("WGPU timing present");
    let (cold_ns, warm_timing, route_ns) =
        super::evidence::gpu_cold_warm_route_evidence(gpu_timing)
            .expect("gpu timing must be derivable");
    assert_eq!(decision.gpu_cold_ns(), Some(cold_ns));
    assert_eq!(decision.gpu_warm_ms(), Some(warm_timing.median_ms()));
    assert_eq!(decision.gpu_route_ns(), Some(route_ns));

    // With no GPU timing, every GPU-derived accessor is `None`: there is no
    // stored copy that could disagree with the (absent) evidence.
    let cpu_only =
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, Some(9), None);
    assert_eq!(cpu_only.gpu_ms(), None);
    assert_eq!(cpu_only.gpu_cold_ns(), None);
    assert_eq!(cpu_only.gpu_warm_ms(), None);
    assert_eq!(cpu_only.gpu_route_ns(), None);
}

#[test]
fn autoroute_cache_rejects_selected_route_that_is_not_fastest() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_selected_not_fastest_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, Some(10), None),
        "selected route is not supported by the persisted timing evidence",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("selected route must match persisted confidence-supported route")
            .to_string()
            .contains("selected route is not supported by the persisted timing evidence"),
        "autoroute cache load must not trust a route label that contradicts persisted timing evidence"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_selected_route_beaten_by_separated_confidence() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_selected_overlap_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let simd_timing = BackendTimingEvidence::from_trial_ns(vec![
        10_000_000, 30_000_000, 30_000_000, 30_000_000, 30_000_000, 30_000_000, 30_000_000,
    ])
    .expect("valid noisy SIMD timing");
    let cpu_timing = BackendTimingEvidence::from_trial_ns(vec![
        11_000_000, 11_000_000, 11_000_000, 11_000_000, 11_000_000, 11_000_000, 11_000_000,
    ])
    .expect("valid steady CPU timing");
    let bad = AutorouteDecision::from_timing_evidence(
        ScanBackend::SimdCpu,
        8 * 1024 * 1024,
        1,
        0xA11D_0B57_A11D_0B57,
        1,
        simd_timing,
        Some(cpu_timing),
        None,
    );
    // SIMD has one lucky 10ms trial but a wide CI centred near 30ms; CPU is a
    // steady 11ms with a tight CI entirely below SIMD's. Routing is decided from
    // confidence intervals, never the single best trial, so CPU is the provably
    // fastest route and a SIMD selection must be rejected, a lucky outlier can
    // never win over a steadily-faster backend.
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key.clone(),
        bad,
        "selected route is not supported by the persisted timing evidence",
    );
    let inspection = inspect_autoroute_cache(Some(&path));
    assert!(
        inspection
            .error
            .as_deref()
            .is_some_and(|error| {
                error.contains("structurally invalid")
                    && error.contains("not supported by the persisted timing evidence")
            }),
        "inspection must surface invalid route evidence instead of silently omitting its row: {inspection:?}"
    );
    assert!(
        inspection.configs.is_empty(),
        "inspection must not present a partially valid cache after one decision fails validation"
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("a lucky-outlier backend must be rejected for the CI-faster route")
            .to_string()
            .contains("selected route is not supported by the persisted timing evidence"),
        "autoroute cache load must route by confidence interval, not a single best_ns trial"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

// --- Exact bucket resolution ------------------------------------------------

fn cpu_decision(backend: ScanBackend) -> AutorouteDecision {
    match backend {
        ScanBackend::SimdCpu => {
            AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None)
        }
        ScanBackend::CpuFallback => AutorouteDecision::new(
            ScanBackend::CpuFallback,
            8 * 1024 * 1024,
            1,
            13,
            Some(7),
            None,
        ),
        other => panic!("cpu_decision only builds CPU-class backends, got {other:?}"),
    }
}

fn gpu_decision() -> AutorouteDecision {
    AutorouteDecision::new(ScanBackend::GpuWgpu, 8 * 1024 * 1024, 1, 20, None, Some(5))
}

#[test]
fn bucket_resolution_exact_hit_wins() {
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(key.clone(), cpu_decision(ScanBackend::SimdCpu));
    assert_eq!(
        resolve_bucket(&decisions, &key),
        BucketResolution::Exact(ScanBackend::SimdCpu)
    );
}

#[test]
fn bucket_resolution_rejects_agreeing_cpu_neighbours() {
    // Matching CPU decisions on neighbouring size buckets do not prove which
    // backend is fastest for the unmeasured bucket.
    let base = test_workload_key();
    let lo = WorkloadKey {
        bytes_bucket: 8,
        ..base.clone()
    };
    let hi = WorkloadKey {
        bytes_bucket: 12,
        ..base.clone()
    };
    let mut decisions = HashMap::new();
    decisions.insert(lo, cpu_decision(ScanBackend::SimdCpu));
    decisions.insert(hi, cpu_decision(ScanBackend::SimdCpu));
    let requested = WorkloadKey {
        bytes_bucket: 10,
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

#[test]
fn persisted_router_rejects_agreeing_neighbours_without_exact_evidence() {
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 12,
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    let requested = WorkloadKey {
        bytes_bucket: 10,
        ..base.clone()
    };

    let error = resolve_persisted_route(
        &decisions,
        requested,
        AutorouteRuntimeClass::OneShot,
        &Some(std::path::PathBuf::from("autoroute.json")),
        &None,
    )
    .expect_err("production autoroute lookup must require an exact bucket");
    assert!(
        error
            .to_string()
            .contains("no persisted fastest-correct backend decision"),
        "missing exact evidence must surface the calibration error: {error}"
    );
}

#[test]
fn persistent_daemon_route_uses_warm_gpu_evidence_but_one_shot_uses_cold_cost() {
    let simd =
        BackendTimingEvidence::from_trial_ns(vec![10_000_000; 7]).expect("SIMD timing evidence");
    let cpu =
        BackendTimingEvidence::from_trial_ns(vec![20_000_000; 7]).expect("CPU timing evidence");
    let mut gpu_trials = vec![100_000_000];
    gpu_trials.extend(std::iter::repeat_n(1_000_000, 6));
    let gpu = BackendTimingEvidence::from_trial_ns(gpu_trials).expect("GPU timing evidence");
    let decision = AutorouteDecision::from_timing_evidence(
        ScanBackend::SimdCpu,
        8 * 1024 * 1024,
        9,
        0xA11D,
        1,
        simd,
        Some(cpu),
        Some(gpu),
    );

    assert_eq!(
        decision.resolved_routing_backend(),
        Some(ScanBackend::SimdCpu),
        "one-shot routing must include the real GPU cold dispatch cost"
    );
    assert_eq!(
        decision.resolved_persistent_backend(),
        Some(ScanBackend::GpuWgpu),
        "a preinitialized daemon must select from warm GPU evidence"
    );
    assert!(
        decision.has_confidence_supported_route()
            && decision.has_confidence_supported_persistent_route(),
        "the fixture must provide separated evidence for both runtime classes"
    );
    assert_eq!(
        decision.selected_margin_ns(),
        Some(10_000_000),
        "one-shot SIMD beats the next one-shot candidate by 10 ms"
    );
    assert_eq!(
        decision.persistent_selected_margin_ns(),
        Some(9_000_000),
        "warm GPU beats persistent SIMD by 9 ms"
    );
}

#[test]
fn persistent_daemon_route_uses_warm_simd_evidence_but_one_shot_includes_materialization() {
    let simd = BackendTimingEvidence::from_trial_ns(vec![
        100_000_000,
        10_000_000,
        10_000_000,
        10_000_000,
        10_000_000,
        10_000_000,
        10_000_000,
    ])
    .expect("SIMD cold/warm timing evidence");
    let cpu =
        BackendTimingEvidence::from_trial_ns(vec![30_000_000; 7]).expect("CPU timing evidence");
    let decision = AutorouteDecision::from_timing_evidence(
        ScanBackend::CpuFallback,
        8 * 1024 * 1024,
        1,
        0x51AD,
        1,
        simd,
        Some(cpu),
        None,
    );

    assert_eq!(
        decision.resolved_routing_backend(),
        Some(ScanBackend::CpuFallback),
        "one-shot routing must include Hyperscan materialization"
    );
    assert_eq!(
        decision.resolved_persistent_backend(),
        Some(ScanBackend::SimdCpu),
        "a persistent daemon must select from warm Hyperscan trials"
    );
}

#[test]
fn daemon_warm_routes_come_only_from_persisted_selected_backends() {
    let timing = |ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS);
    let mut decisions = HashMap::new();
    decisions.insert(test_workload_key(), cpu_decision(ScanBackend::SimdCpu));
    decisions.insert(
        WorkloadKey {
            bytes_bucket: test_workload_key().bytes_bucket + 1,
            ..test_workload_key()
        },
        AutorouteDecision::from_peer_timing_evidence(
            ScanBackend::GpuCuda,
            8 * 1024 * 1024,
            1,
            test_measurement_shape_evidence(8 * 1024 * 1024, 1),
            7,
            1,
            route_timings(
                timing(30),
                Some(timing(40)),
                Some(timing(8)),
                Some(timing(16)),
                Some(timing(1_030)),
                Some(timing(1_040)),
                Some(timing(1_008)),
                Some(timing(1_016)),
            ),
            false,
            false,
        ),
    );
    let router = CachedBackendRouter {
        pattern_count: 922,
        decode_workload_plan: test_decode_workload_plan(),
        decisions,
        cache_path: None,
        cache_load_error: None,
        runtime_class: AutorouteRuntimeClass::OneShot,
        runtime_faults: Mutex::new(HashMap::new()),
        runtime_health: None,
        recovery_announced: AtomicBool::new(false),
    };

    assert_eq!(
        router
            .persistent_routes()
            .expect("complete persisted routes"),
        vec![ScanBackend::GpuCuda, ScanBackend::SimdCpu],
        "daemon warm-up must include exactly every selected accelerator"
    );
    assert_eq!(
        router
            .persistent_gpu_routes()
            .expect("complete persisted routes"),
        vec![ScanBackend::GpuCuda],
        "CPU-selected rows and unused WGPU peers must not enter daemon warm-up"
    );
}

#[test]
fn daemon_without_valid_autoroute_evidence_initializes_scalar_recovery() {
    let router = CachedBackendRouter {
        pattern_count: 922,
        decode_workload_plan: test_decode_workload_plan(),
        decisions: HashMap::new(),
        cache_path: Some(std::path::PathBuf::from("missing-autoroute.json")),
        cache_load_error: Some("cache schema is stale".to_string()),
        runtime_class: AutorouteRuntimeClass::OneShot,
        runtime_faults: Mutex::new(HashMap::new()),
        runtime_health: None,
        recovery_announced: AtomicBool::new(false),
    };

    assert_eq!(
        router
            .persistent_routes()
            .expect("invalid autoroute state must not prevent daemon readiness"),
        vec![ScanBackend::CpuFallback],
        "daemon readiness must initialize only the scalar correctness recovery route"
    );
}

#[test]
fn bucket_resolution_rejects_neighbours_along_max_file_axis() {
    // The exactness requirement applies independently to every workload axis.
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            max_file_bucket: 4,
            ..base.clone()
        },
        cpu_decision(ScanBackend::CpuFallback),
    );
    decisions.insert(
        WorkloadKey {
            max_file_bucket: 10,
            ..base.clone()
        },
        cpu_decision(ScanBackend::CpuFallback),
    );
    let requested = WorkloadKey {
        max_file_bucket: 7,
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

#[test]
fn bucket_resolution_fails_closed_when_cpu_neighbours_disagree() {
    // SimdCpu below, CpuFallback above: the backend choice is NOT stable across
    // the interval, so the in-between bucket must fail closed (never guess one).
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 12,
            ..base.clone()
        },
        cpu_decision(ScanBackend::CpuFallback),
    );
    let requested = WorkloadKey {
        bytes_bucket: 10,
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

#[test]
fn bucket_resolution_never_interpolates_across_gpu_buckets() {
    // GPU correctness can vary with input size (cf. #18), so even two agreeing
    // GPU neighbours must NOT generalize (the in-between bucket fails closed).
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            ..base.clone()
        },
        gpu_decision(),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 12,
            ..base.clone()
        },
        gpu_decision(),
    );
    let requested = WorkloadKey {
        bytes_bucket: 10,
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

#[test]
fn bucket_resolution_requires_both_brackets() {
    // Only a lower neighbour exists (nothing above the requested size): the
    // bucket is not bracketed, so there is no sound interpolation.
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    let requested = WorkloadKey {
        bytes_bucket: 10,
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

#[test]
fn bucket_resolution_does_not_cross_non_size_dimensions() {
    // Neighbours that differ on a NON-size dimension (here source mixture)
    // describe a different workload shape and must not bracket the request.
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            source_mixture: test_source_mixture("filesystem"),
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 12,
            source_mixture: test_source_mixture("filesystem"),
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    let requested = WorkloadKey {
        bytes_bucket: 10,
        source_mixture: test_source_mixture("web"),
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

// --- Below-floor workloads still require exact evidence ---------------------

#[test]
fn bucket_resolution_rejects_below_floor_cpu_extrapolation() {
    // Fixed setup cost alone cannot prove the fastest backend for an unmeasured
    // smaller workload, so even a CPU-only calibrated frontier must fail closed.
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            max_file_bucket: 8,
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 12,
            max_file_bucket: 12,
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    let requested = WorkloadKey {
        bytes_bucket: 3,
        max_file_bucket: 3,
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

#[test]
fn bucket_resolution_rejects_between_single_file_rungs() {
    // Correlated bytes/max-file buckets are still a distinct unmeasured workload
    // identity; agreeing endpoints are not a calibrated decision for the middle.
    let base = test_workload_key();
    let lo = WorkloadKey {
        bytes_bucket: 6,
        max_file_bucket: 6,
        ..base.clone()
    };
    let hi = WorkloadKey {
        bytes_bucket: 8,
        max_file_bucket: 8,
        ..base.clone()
    };
    let mut decisions = HashMap::new();
    decisions.insert(lo, cpu_decision(ScanBackend::SimdCpu));
    decisions.insert(hi, cpu_decision(ScanBackend::SimdCpu));
    let requested = WorkloadKey {
        bytes_bucket: 7,
        max_file_bucket: 7,
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

#[test]
fn bucket_resolution_does_not_interpolate_between_disagreeing_single_file_rungs() {
    // The diagonal bracket is only sound when both single-file rungs AGREE: a query
    // between a SimdCpu rung and a CpuFallback rung has no single fastest-correct
    // answer, so it must stay fail-closed (Unresolved), never guess one side.
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 6,
            max_file_bucket: 6,
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            max_file_bucket: 8,
            ..base.clone()
        },
        cpu_decision(ScanBackend::CpuFallback),
    );
    let requested = WorkloadKey {
        bytes_bucket: 7,
        max_file_bucket: 7,
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved,
        "disagreeing single-file brackets must fail closed, not pick a side"
    );
}

#[test]
fn bucket_resolution_does_not_interpolate_single_file_across_a_gpu_rung() {
    // GPU correctness varies with input size, so it can never anchor a diagonal
    // bracket: a single-file query whose only upper neighbour is GPU has just one
    // CPU side (the lower rung) and stays fail-closed, never a one-sided guess and
    // never a clamp toward GPU.
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 6,
            max_file_bucket: 6,
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            max_file_bucket: 8,
            ..base.clone()
        },
        gpu_decision(),
    );
    let requested = WorkloadKey {
        bytes_bucket: 7,
        max_file_bucket: 7,
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved,
        "a GPU rung must not anchor a single-file diagonal bracket"
    );
}

#[test]
fn bucket_resolution_does_not_clamp_below_a_gpu_floor() {
    // GPU correctness can vary with input size, so a below-floor query whose only
    // calibrated neighbour is GPU must still fail closed, never clamp to GPU, and
    // no CPU-class evidence exists for this class.
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            ..base.clone()
        },
        gpu_decision(),
    );
    let requested = WorkloadKey {
        bytes_bucket: 3,
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

#[test]
fn bucket_resolution_does_not_clamp_an_uncalibrated_class() {
    // No calibrated bucket shares the request's non-size dimensions: the workload
    // CLASS itself was never calibrated, so there is no floor to clamp under
    // fail closed rather than invent one.
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            source_mixture: test_source_mixture("filesystem"),
            ..base.clone()
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    let requested = WorkloadKey {
        bytes_bucket: 3,
        source_mixture: test_source_mixture("web"),
        ..base.clone()
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

#[test]
fn cuda_and_wgpu_are_independent_measured_candidates() {
    let timing = |ms| BackendTimingEvidence::constant_ms(ms, super::AUTOROUTE_CALIBRATION_TRIALS);
    let cuda_wins = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::GpuCuda,
        8 * 1024 * 1024,
        1,
        test_measurement_shape_evidence(8 * 1024 * 1024, 1),
        7,
        1,
        route_timings(
            timing(30),
            Some(timing(40)),
            Some(timing(10)),
            Some(timing(15)),
            Some(timing(1_030)),
            Some(timing(1_040)),
            Some(timing(1_010)),
            Some(timing(1_015)),
        ),
        false,
        false,
    );
    assert_eq!(
        cuda_wins.resolved_routing_backend(),
        Some(ScanBackend::GpuCuda)
    );
    assert_eq!(
        cuda_wins
            .baseline_timing_for_backend(ScanBackend::GpuCuda)
            .map(BackendTimingEvidence::median_ms),
        Some(10)
    );
    assert_eq!(
        cuda_wins
            .baseline_timing_for_backend(ScanBackend::GpuWgpu)
            .map(BackendTimingEvidence::median_ms),
        Some(15)
    );

    let wgpu_wins = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::GpuWgpu,
        8 * 1024 * 1024,
        1,
        test_measurement_shape_evidence(8 * 1024 * 1024, 1),
        7,
        1,
        route_timings(
            timing(30),
            Some(timing(40)),
            Some(timing(16)),
            Some(timing(9)),
            Some(timing(1_030)),
            Some(timing(1_040)),
            Some(timing(1_016)),
            Some(timing(1_009)),
        ),
        false,
        false,
    );
    assert_eq!(
        wgpu_wins.resolved_routing_backend(),
        Some(ScanBackend::GpuWgpu)
    );

    let json = serde_json::to_value(&wgpu_wins).expect("serialize peer evidence");
    let point = &json["calibration_points"][0];
    let timings = point["route_timings"]
        .as_array()
        .expect("generic route timing array");
    assert_eq!(timings.len(), 16);
    assert!(timings.iter().any(|entry| {
        entry["backend"] == ScanBackend::GpuCuda.label()
            && entry["phase2_plain_localizer"] == true
            && entry["phase2_keyword_localizer"] == true
    }));
    assert!(timings.iter().any(|entry| {
        entry["backend"] == ScanBackend::GpuWgpu.label()
            && entry["phase2_plain_localizer"] == false
            && entry["phase2_keyword_localizer"] == true
    }));
    assert!(point.get("gpu_timing").is_none());
}

#[test]
fn phase2_plain_localizer_is_an_independent_measured_route_candidate() {
    let timing = |ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS);
    let decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::SimdCpu,
        8 * 1024 * 1024,
        8,
        test_measurement_shape_evidence(8 * 1024 * 1024, 8),
        7,
        1,
        route_timings(
            timing(30),
            Some(timing(45)),
            None,
            None,
            Some(timing(8)),
            Some(timing(20)),
            None,
            None,
        ),
        false,
        false,
    );

    let route = decision
        .resolved_routing_route()
        .expect("route evidence resolves");
    assert_eq!(route.backend, ScanBackend::SimdCpu);
    assert!(route.phase2_plain_localizer);
    assert_eq!(
        decision.primary_point().candidate_receipts.len(),
        8,
        "all four localization plans need independent parity receipts for each eligible backend"
    );
}

#[test]
fn phase2_keyword_localizer_is_an_independent_measured_route_candidate() {
    let timing = |ms| BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS);
    let mut timings = route_timings(
        timing(30),
        Some(timing(45)),
        None,
        None,
        Some(timing(40)),
        Some(timing(50)),
        None,
        None,
    );
    let keyword_route = MeasuredRoute {
        backend: ScanBackend::SimdCpu,
        phase2_plain_localizer: false,
        phase2_keyword_localizer: true,
    };
    timings
        .iter_mut()
        .find(|entry| entry.measured_route() == Some(keyword_route))
        .expect("keyword-localizer route timing")
        .timing = timing(8);
    let decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::SimdCpu,
        8 * 1024 * 1024,
        8,
        test_measurement_shape_evidence(8 * 1024 * 1024, 8),
        7,
        1,
        timings,
        false,
        false,
    );

    assert_eq!(decision.resolved_routing_route(), Some(keyword_route));
    assert_eq!(decision.primary_point().candidate_receipts.len(), 8);
}

#[cfg(feature = "default")]
#[test]
fn live_calibration_measures_every_gpu_peer_before_resolving_or_refusing() {
    let detector = keyhog_core::DetectorSpec {
        id: "gpu-peer-calibration".into(),
        name: "GPU peer calibration".into(),
        service: "test".into(),
        severity: keyhog_core::Severity::High,
        patterns: vec![keyhog_core::PatternSpec {
            regex: "KHGPUCAL_[A-Za-z0-9]{20}".into(),
            description: None,
            group: None,
            required_literals: Vec::new(),
            client_safe: false,
            weak_anchor: false,
            structural_password_slot: false,
        }],
        keywords: vec!["KHGPUCAL".into()],
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    };
    let scanner = CompiledScanner::compile(vec![detector]).expect("compile calibration scanner");
    let candidates = scanner.gpu_backend_candidates();
    assert!(
        candidates
            .iter()
            .find(|candidate| candidate.backend == ScanBackend::GpuCuda)
            .is_some_and(|candidate| candidate.available),
        "CUDA peer must be live on the GPU release host"
    );
    assert!(
        candidates
            .iter()
            .find(|candidate| candidate.backend == ScanBackend::GpuWgpu)
            .is_some_and(|candidate| candidate.available),
        "WGPU peer must be live on the GPU release host"
    );
    let sample = vec![Chunk {
        data: "key=KHGPUCAL_A1b2C3d4E5f6G7h8I9j0\n".repeat(1024).into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    }];
    let eligible = super::eligible_backend_labels(&scanner, true);
    let admission_plan = scanner.phase1_admission_plan(&sample);
    let outcome = super::calibration::calibrate_fastest_correct_backend(
        &scanner,
        0,
        &sample,
        test_measurement_shape_evidence(
            sample.iter().map(|chunk| chunk.data.len() as u64).sum(),
            sample.len(),
        ),
        &eligible,
        Some(&admission_plan),
    );
    match outcome {
        Ok(decision) => {
            assert!(decision
                .primary_point()
                .baseline_timing_for_backend(ScanBackend::GpuCuda)
                .is_some());
            assert!(decision
                .primary_point()
                .baseline_timing_for_backend(ScanBackend::GpuWgpu)
                .is_some());
            assert!(decision.backend().is_some());
        }
        Err(error) => {
            let diagnostic = error.to_string();
            assert!(
                diagnostic.contains("calibration timing is inconclusive")
                    && diagnostic.contains(ScanBackend::GpuCuda.label())
                    && diagnostic.contains(ScanBackend::GpuWgpu.label())
                    && diagnostic.contains("median_ns=")
                    && diagnostic.contains("ci95_ns=["),
                "an honest refusal must prove that both live GPU peers were measured and expose why no winner exists: {diagnostic}"
            );
        }
    }
}
