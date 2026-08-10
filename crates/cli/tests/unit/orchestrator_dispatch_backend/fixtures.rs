use super::super::evidence::*;
use super::super::host::*;
use super::super::store::*;
use super::super::workload::decode_workload_sketch as decode_workload_sketch_with_plan;
use super::super::workload::workload_key as workload_key_with_plan;
use super::super::workload::*;
use super::super::*;
use std::result::Result as StdResult;
pub(crate) fn route_timings(
    simd: BackendTimingEvidence,
    cpu: Option<BackendTimingEvidence>,
    cuda: Option<BackendTimingEvidence>,
    metal: Option<BackendTimingEvidence>,
    wgpu: Option<BackendTimingEvidence>,
    simd_plain: Option<BackendTimingEvidence>,
    cpu_plain: Option<BackendTimingEvidence>,
    cuda_plain: Option<BackendTimingEvidence>,
    metal_plain: Option<BackendTimingEvidence>,
    wgpu_plain: Option<BackendTimingEvidence>,
) -> Vec<RouteTimingEvidence> {
    let mut routes = Vec::new();
    for (backend, base, plain) in [
        (ScanBackend::SimdCpu, Some(simd), simd_plain),
        (ScanBackend::CpuFallback, cpu, cpu_plain),
        (ScanBackend::GpuCuda, cuda, cuda_plain),
        (ScanBackend::GpuMetal, metal, metal_plain),
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
                    gpu_pipeline_depth: 1,
                },
                timing,
            ));
        }
    }
    routes
}

pub(crate) fn route_timing_mut(
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

pub(crate) fn test_decode_workload_plan() -> keyhog_scanner::decode::DecodeWorkloadPlan {
    keyhog_scanner::decode::DecodeWorkloadPlan::from_limits(1, usize::MAX)
}

pub(crate) fn test_eligible_backends(gpu: Option<ScanBackend>) -> Vec<String> {
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
pub(crate) fn test_scanner_eligible_backends(
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

pub(crate) fn workload_key(
    batch: &[Chunk],
    pattern_count: usize,
) -> StdResult<WorkloadKey, super::super::workload::WorkloadClassificationError> {
    workload_key_with_plan(
        batch,
        pattern_count,
        all_admitted_phase1(batch),
        keyhog_scanner::Phase2KeywordTriggerSummary::default(),
        test_decode_workload_plan(),
    )
}

pub(crate) fn all_admitted_phase1(batch: &[Chunk]) -> keyhog_scanner::Phase1AdmissionSummary {
    keyhog_scanner::Phase1AdmissionSummary::all_admitted(
        batch.len() as u64,
        batch.iter().map(|chunk| chunk.data.len() as u64).sum(),
    )
}

pub(crate) fn phase1_test_scanner() -> CompiledScanner {
    CompiledScanner::compile(phase1_test_detectors()).expect("autoroute phase-1 scanner compiles")
}

pub(crate) fn phase2_keyword_test_scanner() -> CompiledScanner {
    let mut detectors = phase1_test_detectors();
    detectors[0].patterns[0].regex = r"[gG][hH][pP]_[A-Za-z0-9]{8}".into();
    CompiledScanner::compile(detectors).expect("autoroute phase-2 scanner compiles")
}

pub(crate) fn phase1_test_detectors() -> Vec<keyhog_core::DetectorSpec> {
    let baseline = keyhog_core::embedded_detector_specs()
        .iter()
        .find(|detector| detector.id == "generic-password")
        .expect("embedded generic-password policy") // keyhog:ignore detector=cli-password-flag
        .clone();
    vec![keyhog_core::DetectorSpec {
        tests: Vec::new(),
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
        ..baseline
    }]
}

pub(crate) fn repeated_to_len(seed: &str, len: usize) -> String {
    let mut value = seed.repeat(len.div_ceil(seed.len()));
    value.truncate(len);
    value
}

pub(crate) fn decode_workload_sketch(
    batch: &[Chunk],
) -> keyhog_scanner::decode::DecodeAdmissionSketch {
    decode_workload_sketch_with_plan(batch, test_decode_workload_plan())
}

pub(crate) fn test_host(gpu_name: Option<&str>) -> AutorouteHostProfile {
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

pub(crate) fn test_workload_key() -> WorkloadKey {
    WorkloadKey {
        bytes_bucket: 24,
        chunks_bucket: 1,
        max_file_bucket: 24,
        pattern_bucket: 5,
        phase2_keyword_triggers: Phase2KeywordTriggerKey {
            chunks_bucket: 0,
            bytes_bucket: 0,
            count_bucket: 0,
        },
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

pub(crate) fn test_source_mixture(source_class: &str) -> SourceMixtureKey {
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

pub(crate) fn test_hw_caps() -> keyhog_scanner::hw_probe::HardwareCaps {
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

pub(crate) fn write_tampered_decision_cache(
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

pub(crate) fn valid_decision_for_host(host: &AutorouteHostProfile) -> AutorouteDecision {
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
            has(ScanBackend::GpuMetal).then(|| timing(35)),
            has(ScanBackend::GpuWgpu).then(|| timing(40)),
            Some(timing(1_012)),
            Some(timing(1_020)),
            has(ScanBackend::GpuCuda).then(|| timing(1_030)),
            has(ScanBackend::GpuMetal).then(|| timing(1_035)),
            has(ScanBackend::GpuWgpu).then(|| timing(1_040)),
        ),
        false,
        false,
    )
}

pub(crate) fn test_rules_digest() -> &'static str {
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

pub(crate) fn test_chunk(data: String) -> Chunk {
    test_chunk_with_source(data, "filesystem")
}

pub(crate) fn test_chunk_with_source(data: String, source_type: &str) -> Chunk {
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
