use super::evidence::{
    canonical_matches, canonical_matches_equal_reference, AutorouteDecision, BackendTimingEvidence,
};
use super::host::AutorouteHostProfile;
use super::store::{
    load_autoroute_cache, resolve_bucket, save_autoroute_cache, AutorouteBuildFeatures,
    AutorouteCache, BucketResolution, AUTOROUTE_CACHE_FILE_BYTES,
};
use super::workload::{
    autoroute_stable_bucket, autoroute_stable_density_bucket, source_class_hash, workload_key,
    WorkloadKey,
};
use super::*;

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
}

#[test]
fn autoroute_host_identity_uses_dependency_owned_gpu_compile_fact() {
    let mut caps = test_hw_caps();
    caps.gpu_available = true;
    caps.gpu_name = Some("NVIDIA GeForce RTX 5090".to_string());
    caps.gpu_runtime_identity = Some("cuda:NVIDIA:RTX5090:driver-565".to_string());

    let profile = AutorouteHostProfile::from_caps(
        &caps,
        Some("cuda"),
        keyhog_scanner::hw_probe::gpu_backend_compiled(),
    );
    if keyhog_scanner::hw_probe::gpu_backend_compiled() {
        assert_eq!(profile.gpu_name, caps.gpu_name);
        assert_eq!(profile.gpu_runtime_backend.as_deref(), Some("cuda"));
        assert_eq!(
            profile.gpu_driver_runtime_identity,
            caps.gpu_runtime_identity
        );
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
        gpu_name: gpu_name.map(str::to_string),
        gpu_runtime_backend: gpu_name.map(|_| "cuda".to_string()),
        gpu_driver_runtime_identity: gpu_name.map(|name| format!("wgpu:Vulkan:{name}:535.00")),
        gpu_is_software: false,
        total_memory_mb: Some(65_536),
    }
}

fn test_workload_key() -> WorkloadKey {
    WorkloadKey {
        bytes_bucket: 10,
        chunks_bucket: 2,
        max_file_bucket: 8,
        pattern_bucket: 5,
        decode_density_bucket: 3,
        source_class_hash: 0xAA55_AA55_AA55_AA55,
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
    }
}

#[test]
fn host_profile_strips_gpu_runtime_when_no_hardware_gpu_participates() {
    let mut cpu_only = test_hw_caps();
    cpu_only.gpu_available = false;
    cpu_only.gpu_name = Some("stale probe name".to_string());
    cpu_only.gpu_runtime_identity = Some("stale runtime identity".to_string());
    cpu_only.gpu_is_software = false;
    let cpu_profile = AutorouteHostProfile::from_caps(&cpu_only, Some("cuda"), true);
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
    let software_profile = AutorouteHostProfile::from_caps(&software_gpu, Some("wgpu"), true);
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
fn no_gpu_build_calibrates_on_a_host_that_has_a_physical_gpu() {
    // Regression: a portable / no-`gpu`-feature build on a workstation WITH a
    // discrete GPU. The hardware probe sees the card, but no wgpu runtime is
    // compiled, so `runtime_status.gpu_backend` is None. Before the fix this
    // tripped `require_exact_identity` ("GPU runtime backend identity is
    // unavailable") and `keyhog scan --autoroute-calibrate` / `install.sh
    // --calibrate` failed closed on EVERY GPU box for the portable binary. A
    // no-gpu build must collapse the (unusable) GPU dimension and calibrate
    // SIMD/CPU-only.
    let mut gpu_host = test_hw_caps();
    gpu_host.gpu_available = true;
    gpu_host.gpu_name = Some("NVIDIA GeForce RTX 5090".to_string());
    gpu_host.gpu_runtime_identity = Some("wgpu:Vulkan:NVIDIA:565.00".to_string());
    gpu_host.gpu_is_software = false;

    // gpu_supported_by_build = false → this build can never route to the GPU.
    let mut portable = AutorouteHostProfile::from_caps(&gpu_host, None, false);
    assert_eq!(
        portable.gpu_name, None,
        "no-gpu build records no GPU device identity for an unusable card"
    );
    assert_eq!(
        portable.gpu_runtime_backend, None,
        "no-gpu build records no GPU runtime backend"
    );
    assert_eq!(
        portable.gpu_driver_runtime_identity, None,
        "no-gpu build records no GPU driver identity"
    );
    assert!(
        !portable.gpu_is_software,
        "no-gpu build carries no GPU software flag"
    );
    // Isolate the GPU invariant from real-host cpuinfo so the test is hermetic.
    portable.cpu_model = Some("test-cpu".to_string());
    portable
        .require_exact_identity()
        .expect("a no-gpu build must calibrate on a host that has a physical GPU");

    // Contrast: a GPU-CAPABLE build whose runtime probe FAILED (gpu_backend
    // None) must STILL fail closed, the physical GPU IS usable by this build,
    // so caching GPU-absent evidence would silently mis-route (Law 10).
    let mut gpu_build_probe_failed = AutorouteHostProfile::from_caps(&gpu_host, None, true);
    gpu_build_probe_failed.cpu_model = Some("test-cpu".to_string());
    assert_eq!(
        gpu_build_probe_failed.require_exact_identity(),
        Err("GPU runtime backend identity is unavailable"),
        "a GPU-capable build that sees the card but got no runtime backend must fail closed"
    );
}

#[test]
fn gpu_capable_build_rejects_present_gpu_without_device_name() {
    let mut caps = test_hw_caps();
    caps.gpu_available = true;
    caps.gpu_name = None;
    caps.gpu_runtime_identity = Some("cuda:unknown-device:driver-565".to_string());

    let mut profile = AutorouteHostProfile::from_caps(&caps, Some("cuda"), true);
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
    bad_decisions.insert(key, bad_decision.clone());
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
    valid_decisions.insert(
        key,
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
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
    config.decisions.clear();
    config.decisions.push((key, bad_decision));
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&cache).expect("tampered cache serializes"),
    )
    .expect("tampered cache writable");
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
fn workload_key_distinguishes_decode_density_for_same_size_batches() {
    let encoded = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=".repeat(128);
    let mut plain = "id: x\npath: ./src\n".repeat((encoded.len() / 18) + 1);
    plain.truncate(encoded.len());
    let plain_key = workload_key(&[test_chunk(plain)], 902).expect("plain workload classified");
    let encoded_key =
        workload_key(&[test_chunk(encoded)], 902).expect("encoded workload classified");

    assert_eq!(plain_key.bytes_bucket, encoded_key.bytes_bucket);
    assert_eq!(plain_key.chunks_bucket, encoded_key.chunks_bucket);
    assert_eq!(plain_key.max_file_bucket, encoded_key.max_file_bucket);
    assert_eq!(plain_key.pattern_bucket, encoded_key.pattern_bucket);
    assert_eq!(plain_key.source_class_hash, encoded_key.source_class_hash);
    assert!(
        encoded_key.decode_density_bucket > plain_key.decode_density_bucket,
        "autoroute workload keys must separate decode-heavy inputs from same-size plain text"
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
        autoroute_stable_density_bucket(7),
        autoroute_stable_density_bucket(8),
        "adjacent decode-density sample jitter must not invalidate calibration"
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
    let representative_counts = [1usize, 4, 16, 32];
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
fn source_class_hash_uses_stable_top_level_source_family() {
    let plain = source_class_hash(&[test_chunk_with_source("a".repeat(64), "filesystem")])
        .expect("filesystem source class hashes");
    let mixed_filesystem = source_class_hash(&[
        test_chunk_with_source("a".repeat(64), "filesystem/windowed"),
        test_chunk_with_source("a".repeat(64), "filesystem/archive"),
    ])
    .expect("filesystem subtype source classes hash");
    let docker = source_class_hash(&[test_chunk_with_source("a".repeat(64), "docker")])
        .expect("docker source class hashes");

    assert_eq!(
        plain, mixed_filesystem,
        "filesystem subtype mixtures depend on parallel batch grouping and must route as one family"
    );
    assert_ne!(
        plain, docker,
        "different top-level source families still need separate autoroute cache keys"
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
        full_key.source_class_hash, transformed_key.source_class_hash,
        "autoroute must not reuse full-source measurements for stream/transformation payload sizes"
    );
}

#[test]
fn source_class_hash_associates_size_provenance_with_each_source_family() {
    let mut filesystem = test_chunk_with_source("a".repeat(64), "filesystem/windowed");
    let mut web = test_chunk_with_source("b".repeat(64), "web:js");
    filesystem.metadata.size_bytes = None;
    let filesystem_payload =
        source_class_hash(&[filesystem.clone(), web.clone()]).expect("mixed source classes hash");

    filesystem.metadata.size_bytes = Some(64);
    web.metadata.size_bytes = None;
    let web_payload =
        source_class_hash(&[filesystem, web]).expect("reversed size provenance hashes");

    assert_ne!(
        filesystem_payload, web_payload,
        "equal source sets with different per-family size provenance need distinct calibration keys"
    );
}

#[test]
fn workload_key_rejects_missing_source_class_evidence() {
    let err = workload_key(&[test_chunk_with_source("a".repeat(64), "")], 902)
        .expect_err("autoroute must not hash missing source class as a reusable bucket");
    let text = err.to_string();
    assert!(
        text.contains("source_type") && text.contains("non-empty source family"),
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
    decisions.insert(
        key,
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, Some(40)),
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
    let serialized = std::fs::read_to_string(&path).expect("autoroute cache JSON");
    let version_field = format!("\"version\": {AUTOROUTE_CACHE_VERSION}");
    assert!(
        serialized.contains(&version_field)
            && serialized.contains("\"build_features\"")
            && serialized.contains("\"cli_features\"")
            && serialized.contains("\"scanner_features\"")
            && serialized.contains("\"sources_features\"")
            && serialized.contains("\"verifier_features\"")
            && serialized.contains("\"rules_digest\"")
            && serialized.contains("\"cpu_model\"")
            && serialized.contains("\"physical_cores\"")
            && serialized.contains("\"logical_cores\"")
            && serialized.contains("\"total_memory_mb\"")
            && serialized.contains("\"gpu_runtime_backend\"")
            && serialized.contains("\"gpu_driver_runtime_identity\"")
            && serialized.contains("\"decode_density_bucket\"")
            && serialized.contains("\"correctness_digest\"")
            && serialized.contains("\"calibrated_at_unix_ms\"")
            && serialized.contains("\"simd_timing\"")
            && serialized.contains("\"trials_ns\"")
            && serialized.contains("\"confidence_interval_95_ns\""),
        // v21 persists PRIMARY evidence only: the per-backend ms, GPU
        // cold/warm/route, and selected-margin keys are gone from the JSON
        // they are DERIVED from the timing evidence on load, never stored.
        "cache JSON must persist route timing evidence, not only the selected backend"
    );
    let loaded =
        load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host).unwrap();
    assert_eq!(loaded, decisions);

    let mut replacement = HashMap::new();
    replacement.insert(
        key,
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
                decisions.insert(
                    WorkloadKey {
                        bytes_bucket: index as u8,
                        ..test_workload_key()
                    },
                    cpu_decision(ScanBackend::SimdCpu),
                );
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
    let mut large_key = small_key;
    large_key.bytes_bucket = large_key.bytes_bucket.saturating_add(3);
    assert_ne!(
        small_key, large_key,
        "test needs two distinct workload buckets"
    );

    let mut first = HashMap::new();
    first.insert(
        small_key,
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
        large_key,
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
        key,
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
        key,
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
        key,
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
        key,
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

// F2 regression: on a fast host the routes tie within measurement precision, so
// no single backend is statistically separated. Calibration must still persist a
// SOUND decision (route to the lowest-overhead tied backend) instead of failing
// the whole phase and leaving auto routing with no cache. The selected backend
// must equal `resolved_routing_backend()`; any other choice is rejected.
#[test]
fn tied_calibration_persists_lowest_overhead_backend_not_an_empty_cache() {
    let dir = tempfile::TempDir::new().expect("tempdir for tie calibration");
    let path = dir.path().join("tie-autoroute-cache.json");
    let digest = 0x0FF1_CE00_0FF1_CE00u64;
    let config_digest = 0xD1CE_D1CE_D1CE_D1CEu64;
    let host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();

    // SimdCpu and the GPU route measure identically (20ms) -> overlapping 95%
    // confidence intervals -> a statistical tie. The lowest-overhead member is
    // SimdCpu, so that is the only sound persisted choice.
    let tie_to_simd =
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 20, None, Some(20));
    assert_eq!(
        tie_to_simd.resolved_routing_backend(),
        Some(ScanBackend::SimdCpu),
        "a SimdCpu/GPU tie must resolve to the lowest-overhead route (SimdCpu)"
    );
    let mut decisions = HashMap::new();
    decisions.insert(key, tie_to_simd);
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect("a statistically tied calibration must persist the tie-break, not an empty cache");
    let loaded =
        load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host).unwrap();
    assert_eq!(
        loaded, decisions,
        "tied decision must round-trip through the cache"
    );

    // The SAME tie naming the higher-overhead tied backend (GPU) is NOT the
    // deterministic tie-break and must be rejected on write, a tampered or
    // non-deterministic decision cannot pretend a tie favors the GPU.
    let mut wrong = HashMap::new();
    wrong.insert(
        key,
        AutorouteDecision::new(ScanBackend::Gpu, 8 * 1024 * 1024, 1, 20, None, Some(20)),
    );
    let err = save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &wrong,
    )
    .expect_err("a tie that names the higher-overhead backend must be rejected")
    .to_string();
    assert!(
        err.contains("deterministic tie-break among statistically tied routes"),
        "tie-break rejection should name the contract, got {err:?}"
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
        key,
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
        key,
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
        key,
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
        key,
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    let mut measured_this_run = HashSet::new();
    measured_this_run.insert(key);
    let mut router = MeasuredBackendRouter {
        hw_caps: keyhog_scanner::hw_probe::HardwareCaps {
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
        },
        pattern_count: 902,
        detector_digest: 0x1234_5678_9ABC_DEF0,
        rules_digest: test_rules_digest().to_string(),
        config_digest: 0xA55A_D00D_CAFE_BEEF,
        autoroute_gpu: false,
        calibration_mode: true,
        host_profile: host,
        decisions,
        measured_this_run,
        cache_path: Some(path.clone()),
        cache_load_error: None,
        cache_dirty: true,
    };

    router
        .commit()
        .expect("dirty autoroute cache should commit after successful calibration");
    assert!(
        !router.cache_dirty,
        "successful autoroute cache save must clear the dirty bit so Drop does not rewrite it"
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
        key,
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    {
        let _router = MeasuredBackendRouter {
            hw_caps: keyhog_scanner::hw_probe::HardwareCaps {
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
            },
            pattern_count: 902,
            detector_digest: 0x1234_5678_9ABC_DEF0,
            rules_digest: test_rules_digest().to_string(),
            config_digest: 0xA55A_D00D_CAFE_BEEF,
            autoroute_gpu: false,
            calibration_mode: true,
            host_profile: host,
            decisions,
            measured_this_run: HashSet::new(),
            cache_path: Some(path.clone()),
            cache_load_error: None,
            cache_dirty: true,
        };
    }

    assert!(
        !path.exists(),
        "autoroute must persist only from explicit successful calibration save, never from Drop"
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
    let mut stale_key = measured_key;
    stale_key.bytes_bucket = stale_key.bytes_bucket.saturating_add(1);
    let mut decisions = HashMap::new();
    decisions.insert(
        measured_key,
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None),
    );
    decisions.insert(
        stale_key,
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
    measured_this_run.insert(measured_key);
    let mut router = MeasuredBackendRouter {
        hw_caps: keyhog_scanner::hw_probe::HardwareCaps {
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
        },
        pattern_count: 902,
        detector_digest: 0x1234_5678_9ABC_DEF0,
        rules_digest: test_rules_digest().to_string(),
        config_digest: 0xA55A_D00D_CAFE_BEEF,
        autoroute_gpu: false,
        calibration_mode: true,
        host_profile: host.clone(),
        decisions,
        measured_this_run,
        cache_path: Some(path.clone()),
        cache_load_error: None,
        cache_dirty: true,
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
        key,
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
        hw_caps: keyhog_scanner::hw_probe::HardwareCaps {
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
        },
        pattern_count: 902,
        detector_digest: 0x1234_5678_9ABC_DEF0,
        rules_digest: test_rules_digest().to_string(),
        config_digest: 0xA55A_D00D_CAFE_BEEF,
        autoroute_gpu: false,
        calibration_mode: true,
        host_profile: host,
        decisions,
        measured_this_run: HashSet::new(),
        cache_path: None,
        cache_load_error: None,
        cache_dirty: false,
    };

    assert_eq!(
        router.reusable_decision_backend(&key),
        None,
        "calibration mode must not reuse a persisted cache row before this run remeasures the bucket"
    );
    router.measured_this_run.insert(key);
    assert_eq!(
        router.reusable_decision_backend(&key),
        Some(ScanBackend::CpuFallback),
        "once the bucket is measured during this calibration run, duplicate batches may reuse the new in-memory decision"
    );
}

#[test]
fn cached_router_loads_persisted_decision_and_fails_loud_on_missing_bucket() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_cached_router_hit_miss_{}.json",
        std::process::id()
    ));
    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired pre-state, recall-irrelevant

    let scanner = CompiledScanner::compile_with_gpu_policy(
        Vec::new(),
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    )
    .expect("compile scanner");
    let caps = test_hw_caps();
    let runtime_status = scanner.runtime_status();
    let host = AutorouteHostProfile::from_caps(
        &caps,
        runtime_status.gpu_backend,
        keyhog_scanner::hw_probe::gpu_backend_compiled(),
    );
    let pattern_count = 902;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let hit_batch = vec![test_chunk_with_source(
        "token = abc\n".repeat(64),
        "filesystem",
    )];
    let hit_key = workload_key(&hit_batch, pattern_count).expect("hit workload classified");
    let miss_batch = vec![test_chunk_with_source(
        "token = abc\n".repeat(4096),
        "filesystem",
    )];
    let miss_key = workload_key(&miss_batch, pattern_count).expect("miss workload classified");
    assert_ne!(
        hit_key, miss_key,
        "test must exercise a real cache miss for a different workload bucket"
    );

    let mut decisions = HashMap::new();
    decisions.insert(
        hit_key,
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 9, Some(12), None),
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
        caps,
        pattern_count,
        test_rules_digest().to_string(),
        config_digest,
        Ok(Some(path.clone())),
        &scanner,
    );
    assert_eq!(
        router
            .choose(None, &hit_batch)
            .expect("cache hit should choose persisted backend"),
        ScanBackend::SimdCpu
    );
    let miss = router
        .choose(None, &miss_batch)
        .expect_err("cache miss must fail loud instead of guessing a backend")
        .to_string();
    assert!(
        miss.contains("autoroute calibration required")
            && miss.contains("Normal auto scans never benchmark, guess, or substitute"),
        "cache miss must preserve operator-visible autoroute contract; got {miss}"
    );
    assert_eq!(
        router
            .choose(Some(ScanBackend::CpuFallback), &miss_batch)
            .expect("explicit backend diagnostics bypass autoroute cache"),
        ScanBackend::CpuFallback
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
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
        key,
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
        key,
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
        key,
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
        key,
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
        key,
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
        key,
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
        key,
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
    // Drop the CpuFallback timing so the SELECTED backend has no evidence, the
    // "missing timing" invariant is kept in v21 (the redundant `cpu_ms` field it
    // once also cleared is gone; ms is derived from `cpu_timing`).
    bad.cpu_timing = None;
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
        bad,
        "selected backend is missing timing evidence",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("selected backend without evidence must be rejected")
            .to_string()
            .contains("selected backend is missing timing evidence"),
        "selected backend timing evidence is part of the autoroute trust contract"
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
    bad.sample_bytes = 0;
    bad.sample_chunks = 0;
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
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
fn autoroute_cache_rejects_retired_backend_alias_labels() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_legacy_backend_alias_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();
    let mut bad =
        AutorouteDecision::new(ScanBackend::Gpu, 8 * 1024 * 1024, 1, 12, Some(20), Some(10));
    bad.backend = ["gpu", "zero", "copy"].join("-");
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
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
    // Zero-duration SIMD timing is rejected by the kept `is_valid_for_trials`
    // invariant; v21 removed the redundant `simd_ms` field (derived from timing).
    bad.simd_timing =
        super::evidence::BackendTimingEvidence::constant_ms(0, AUTOROUTE_CALIBRATION_TRIALS);
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
        bad,
        "invalid SIMD timing evidence",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("zero-duration timing evidence must be rejected")
            .to_string()
            .contains("invalid SIMD timing evidence"),
        "autoroute cache load must not trust physically impossible zero-duration timing evidence"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_fabricated_timing_summary_evidence() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_fabricated_timing_summary_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(None);
    let key = test_workload_key();
    let mut bad = AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, None, None);
    bad.simd_timing.mean_ns = bad.simd_timing.mean_ns.saturating_add(1);
    bad.simd_timing.confidence_interval_95_ns.high_ns = bad
        .simd_timing
        .confidence_interval_95_ns
        .high_ns
        .saturating_add(1);
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
        bad,
        "invalid SIMD timing evidence",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("fabricated timing summary evidence must be rejected")
            .to_string()
            .contains("invalid SIMD timing evidence"),
        "autoroute cache load must recompute timing summaries from trials instead of trusting persisted proof fields"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn backend_timing_evidence_rejects_empty_trial_sets_at_construction() {
    assert!(
        super::evidence::BackendTimingEvidence::from_trial_ns(Vec::new()).is_none(),
        "autoroute timing evidence must not convert an empty trial set into a zero-duration route"
    );
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
fn autoroute_reference_inconsistency_aborts_calibration_contract() {
    let error = AutorouteRoutingError::inconsistent_reference_backend(2).to_string();
    assert!(
        error.contains("reference backend produced inconsistent findings")
            && error.contains("no backend decision was persisted"),
        "reference inconsistency must be an autoroute calibration failure, got: {error}"
    );

    let calibration = include_str!("calibration.rs");
    assert!(
        calibration.contains("fn measure_reference_simd(")
            && calibration.contains(
                "Result<(Vec<Vec<keyhog_core::RawMatch>>, BackendTimingEvidence), AutorouteRoutingError>"
            )
            && calibration.contains(
                "scanner.scan_coalesced_with_backend(sample, ScanBackend::SimdCpu)"
            )
            && calibration
                .contains("return Err(AutorouteRoutingError::inconsistent_reference_backend("),
        "measure_reference_simd must explicitly force the SIMD route and abort on reference \
         mismatch, not continue with partial proof"
    );
    assert!(
        !calibration.contains("timed(|| scanner.scan_coalesced(sample))"),
        "autoroute calibration must not label the default coalesced route as explicit SIMD"
    );
    assert!(
        calibration.contains("canonical_matches_equal_reference(&matches, &reference_key)")
            && !calibration.contains("canonical_matches(&matches) != reference_key"),
        "autoroute calibration trial loops must compare against the reference without rebuilding \
         a sorted canonical Vec on every trial"
    );
    assert!(
        !calibration.contains("reference backend produced inconsistent calibration results\"\\n            );\\n            continue;"),
        "old warn-and-continue reference mismatch path must not return"
    );
}

#[test]
fn autoroute_reference_mismatch_evidence_names_divergent_records() {
    let evidence = calibration::calibration_match_identity_set(&[vec![keyhog_core::RawMatch {
        detector_id: "aws-access-key".into(),
        detector_name: "AWS Access Key".into(),
        service: "aws".into(),
        severity: keyhog_core::Severity::High,
        credential: "AKIAIOSFODNN7EXAMPLE".into(),
        credential_hash: [0xAB; 32].into(),
        companions: std::collections::HashMap::new(),
        location: keyhog_core::MatchLocation {
            source: "filesystem".into(),
            file_path: Some("src/secrets.rs".into()),
            line: Some(42),
            offset: 1337,
            commit: None,
            author: None,
            date: None,
        },
        entropy: Some(4.2),
        confidence: Some(0.99),
    }]]);
    let rendered = evidence
        .iter()
        .next()
        .expect("one calibration mismatch identity");

    assert!(
        rendered.contains("chunk=0")
            && rendered.contains("detector=aws-access-key")
            && rendered.contains(
                "cred_hash=abababababababababababababababababababababababababababababababab"
            )
            && rendered.contains("file=Some(\"src/secrets.rs\")")
            && rendered.contains("line=Some(42)")
            && rendered.contains("offset=1337"),
        "autoroute mismatch evidence must name the divergent record, got: {rendered}"
    );
    assert!(
        !rendered.contains("AKIAIOSFODNN7EXAMPLE"),
        "autoroute mismatch diagnostics must not log plaintext credentials: {rendered}"
    );
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
fn autoroute_candidate_rejection_aborts_calibration_contract() {
    let error = AutorouteRoutingError::candidate_backend_rejected(
        ScanBackend::Gpu,
        "candidate findings diverged from the SIMD reference",
    )
    .to_string();
    assert!(
        error.contains("rejected eligible backend gpu")
            && error.contains("cannot prove fastest-correct routing")
            && error.contains("no routing decision was persisted"),
        "eligible candidate rejection must be an autoroute calibration failure, got: {error}"
    );

    let calibration = include_str!("calibration.rs");
    assert!(
        calibration.contains("measure_candidate_backend(")
            && calibration.contains("ScanBackend::CpuFallback")
            && calibration.contains(")?;")
            && calibration
                .contains("return Err(AutorouteRoutingError::candidate_backend_rejected(")
            && calibration.contains("backend rejected by autoroute parity check")
            && calibration.contains("backend rejected by autoroute GPU degrade check")
            && calibration.contains("backend rejected by autoroute GPU cold/warm evidence check"),
        "eligible CPU/GPU candidate rejection must abort calibration instead of dropping the candidate"
    );
    assert!(
        !calibration.contains("if let Some(cpu_timing) = cpu_timing.clone()")
            && !calibration.contains("return None;"),
        "old candidate-drop path must not remain in autoroute calibration"
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
    bad.correctness_digest = 0;
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
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
fn derived_accessors_match_the_persisted_timing_evidence() {
    // v21 REPLACES the old "reject a cache whose STORED cold/warm fields mismatch
    // the timing" contract: those denormalized fields are gone, so the derived
    // values are computed from the timing on demand and CANNOT disagree with it.
    // This proves that ONE-PLACE invariant directly, every accessor reflects the
    // persisted timing evidence exactly, with no second copy that could drift.
    let decision =
        AutorouteDecision::new(ScanBackend::Gpu, 8 * 1024 * 1024, 1, 12, Some(9), Some(20));

    // Per-backend ms derives from the (constant) timing built for each input.
    assert_eq!(decision.simd_ms(), 12);
    assert_eq!(decision.cpu_ms(), Some(9));
    assert_eq!(decision.gpu_ms(), Some(20));

    // GPU cold / warm / route derive from `gpu_timing` through the single owner
    // `gpu_cold_warm_route_evidence`, so the accessors equal a fresh derivation.
    let gpu_timing = decision.gpu_timing.as_ref().expect("gpu timing present");
    let (cold_ns, warm_timing, route_ns) =
        super::evidence::gpu_cold_warm_route_evidence(gpu_timing)
            .expect("gpu timing must be derivable");
    assert_eq!(decision.gpu_cold_ns(), Some(cold_ns));
    assert_eq!(decision.gpu_warm_ms(), Some(warm_timing.best_ms()));
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
fn autoroute_cache_rejects_selected_backend_that_is_not_fastest() {
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
        key,
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 12, Some(10), None),
        "selected backend is not the fastest persisted timing evidence",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("selected backend must match persisted fastest route")
            .to_string()
            .contains("selected backend is not the fastest persisted timing evidence"),
        "autoroute cache load must not trust a backend label that contradicts persisted timing evidence"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}

#[test]
fn autoroute_cache_rejects_selected_backend_with_overlapping_confidence() {
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
        key,
        bad,
        "selected backend is not the fastest persisted timing evidence",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("a lucky-outlier backend must be rejected for the CI-faster route")
            .to_string()
            .contains("selected backend is not the fastest persisted timing evidence"),
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
    AutorouteDecision::new(ScanBackend::Gpu, 8 * 1024 * 1024, 1, 20, None, Some(20))
}

#[test]
fn bucket_resolution_exact_hit_wins() {
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(key, cpu_decision(ScanBackend::SimdCpu));
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
        ..base
    };
    let hi = WorkloadKey {
        bytes_bucket: 12,
        ..base
    };
    let mut decisions = HashMap::new();
    decisions.insert(lo, cpu_decision(ScanBackend::SimdCpu));
    decisions.insert(hi, cpu_decision(ScanBackend::SimdCpu));
    let requested = WorkloadKey {
        bytes_bucket: 10,
        ..base
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
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 12,
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    let requested = WorkloadKey {
        bytes_bucket: 10,
        ..base
    };

    let error = resolve_persisted_backend(
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
        Some(ScanBackend::Gpu),
        "a preinitialized daemon must select from warm GPU evidence"
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
            ..base
        },
        cpu_decision(ScanBackend::CpuFallback),
    );
    decisions.insert(
        WorkloadKey {
            max_file_bucket: 10,
            ..base
        },
        cpu_decision(ScanBackend::CpuFallback),
    );
    let requested = WorkloadKey {
        max_file_bucket: 7,
        ..base
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
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 12,
            ..base
        },
        cpu_decision(ScanBackend::CpuFallback),
    );
    let requested = WorkloadKey {
        bytes_bucket: 10,
        ..base
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
            ..base
        },
        gpu_decision(),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 12,
            ..base
        },
        gpu_decision(),
    );
    let requested = WorkloadKey {
        bytes_bucket: 10,
        ..base
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
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    let requested = WorkloadKey {
        bytes_bucket: 10,
        ..base
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}

#[test]
fn bucket_resolution_does_not_cross_non_size_dimensions() {
    // Neighbours that differ on a NON-size dimension (here source_class_hash)
    // describe a different workload shape and must not bracket the request.
    let base = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            source_class_hash: 0x1111_1111_1111_1111,
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 12,
            source_class_hash: 0x1111_1111_1111_1111,
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    let requested = WorkloadKey {
        bytes_bucket: 10,
        source_class_hash: 0x2222_2222_2222_2222,
        ..base
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
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 12,
            max_file_bucket: 12,
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    let requested = WorkloadKey {
        bytes_bucket: 3,
        max_file_bucket: 3,
        ..base
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
        ..base
    };
    let hi = WorkloadKey {
        bytes_bucket: 8,
        max_file_bucket: 8,
        ..base
    };
    let mut decisions = HashMap::new();
    decisions.insert(lo, cpu_decision(ScanBackend::SimdCpu));
    decisions.insert(hi, cpu_decision(ScanBackend::SimdCpu));
    let requested = WorkloadKey {
        bytes_bucket: 7,
        max_file_bucket: 7,
        ..base
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
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            max_file_bucket: 8,
            ..base
        },
        cpu_decision(ScanBackend::CpuFallback),
    );
    let requested = WorkloadKey {
        bytes_bucket: 7,
        max_file_bucket: 7,
        ..base
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
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    decisions.insert(
        WorkloadKey {
            bytes_bucket: 8,
            max_file_bucket: 8,
            ..base
        },
        gpu_decision(),
    );
    let requested = WorkloadKey {
        bytes_bucket: 7,
        max_file_bucket: 7,
        ..base
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
            ..base
        },
        gpu_decision(),
    );
    let requested = WorkloadKey {
        bytes_bucket: 3,
        ..base
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
            source_class_hash: 0x1111_1111_1111_1111,
            ..base
        },
        cpu_decision(ScanBackend::SimdCpu),
    );
    let requested = WorkloadKey {
        bytes_bucket: 3,
        source_class_hash: 0x2222_2222_2222_2222,
        ..base
    };
    assert_eq!(
        resolve_bucket(&decisions, &requested),
        BucketResolution::Unresolved
    );
}
