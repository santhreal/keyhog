use super::evidence::{
    route_candidates, selected_backend_margin_ns, AutorouteDecision, BackendTimingEvidence,
};
use super::host::AutorouteHostProfile;
use super::store::{
    load_autoroute_cache, save_autoroute_cache, AutorouteCache, AUTOROUTE_CACHE_FILE_BYTES,
};
use super::workload::{
    autoroute_stable_bucket, autoroute_stable_density_bucket, source_class_hash, workload_key,
    WorkloadKey,
};
use super::*;

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
    cache.decisions.clear();
    cache.decisions.push((key, bad_decision));
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
            source_type: source_type.to_string(),
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
        autoroute_stable_bucket(1_u64 << 28),
        "materially different scan sizes still need distinct autoroute buckets"
    );
    assert_eq!(
        autoroute_stable_density_bucket(7),
        autoroute_stable_density_bucket(8),
        "adjacent decode-density sample jitter must not invalidate calibration"
    );
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
            && serialized.contains("\"gpu_cold_ns\"")
            && serialized.contains("\"gpu_warm_ms\"")
            && serialized.contains("\"gpu_warm_timing\"")
            && serialized.contains("\"gpu_route_ns\"")
            && serialized.contains("\"trials_ns\"")
            && serialized.contains("\"confidence_interval_95_ns\"")
            && serialized.contains("\"selected_margin_ns\""),
        "cache JSON must persist route evidence, not only the selected backend"
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
/// message — NOT the opaque serde "missing field …" error a naive full
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
    let duplicate = cache
        .decisions
        .first()
        .expect("saved cache contains one decision")
        .clone();
    cache.decisions.push(duplicate);
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
    cache.decisions.clear();
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
fn autoroute_cache_roundtrips_megascan_backend_decision() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_megascan_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();
    let mut decisions = HashMap::new();
    decisions.insert(
        key,
        AutorouteDecision::new(
            ScanBackend::MegaScan,
            8 * 1024 * 1024,
            1,
            16,
            Some(20),
            Some(10),
        ),
    );

    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect("MegaScan autoroute decision should persist");
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect("MegaScan autoroute decision should reload");
    assert_eq!(
        loaded.get(&key).and_then(AutorouteDecision::backend),
        Some(ScanBackend::MegaScan),
        "persisted MegaScan route evidence must not be relabeled as plain GPU"
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
        cache_path: Some(path.clone()),
        cache_load_error: None,
        cache_dirty: true,
    };

    router
        .save_cache()
        .expect("dirty autoroute cache should save");
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
    let host = AutorouteHostProfile::from_caps(&caps, runtime_status.gpu_backend);
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
    bad.cpu_timing = None;
    bad.cpu_ms = None;
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
fn autoroute_cache_rejects_legacy_backend_alias_labels() {
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
    bad.backend = "gpu-zero-copy".to_string();
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
        bad,
        "non-canonical backend label",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("legacy backend aliases must not be accepted in persisted autoroute proof")
            .to_string()
            .contains("non-canonical backend label"),
        "autoroute cache must require canonical backend labels, not CLI compatibility aliases"
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
    bad.simd_timing =
        super::evidence::BackendTimingEvidence::constant_ms(0, AUTOROUTE_CALIBRATION_TRIALS);
    bad.simd_ms = 0;
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
                "Result<(Vec<CanonicalMatch>, BackendTimingEvidence), AutorouteRoutingError>"
            )
            && calibration
                .contains("return Err(AutorouteRoutingError::inconsistent_reference_backend("),
        "measure_reference_simd must abort on reference mismatch, not continue with partial proof"
    );
    assert!(
        !calibration.contains("reference backend produced inconsistent calibration results\"\\n            );\\n            continue;"),
        "old warn-and-continue reference mismatch path must not return"
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
fn autoroute_cache_rejects_gpu_cold_warm_evidence_mismatch() {
    let path = std::env::temp_dir().join(format!(
        "keyhog_autoroute_gpu_cold_warm_mismatch_{}.json",
        std::process::id()
    ));
    let digest = 0x1234_5678_9ABC_DEF0u64;
    let config_digest = 0xA55A_D00D_CAFE_BEEFu64;
    let host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();
    let mut bad = AutorouteDecision::new(ScanBackend::Gpu, 8 * 1024 * 1024, 1, 12, None, Some(5));
    bad.gpu_cold_ns = bad.gpu_cold_ns.map(|ns| ns.saturating_add(1));
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
        bad,
        "mismatched GPU cold/warm route evidence",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("mismatched GPU cold/warm evidence must be rejected")
            .to_string()
            .contains("mismatched GPU cold/warm route evidence"),
        "GPU autoroute cache trust requires first-dispatch and warmed timing evidence to match the trial distribution"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
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
    let candidates = route_candidates(&simd_timing, Some(&cpu_timing), None);
    let bad = AutorouteDecision::from_timing_evidence(
        ScanBackend::SimdCpu,
        8 * 1024 * 1024,
        1,
        0xA11D_0B57_A11D_0B57,
        1,
        selected_backend_margin_ns(ScanBackend::SimdCpu, &candidates),
        simd_timing,
        Some(cpu_timing),
        None,
        None,
        None,
        None,
    );
    write_tampered_decision_cache(
        &path,
        digest,
        config_digest,
        &host,
        key,
        bad,
        "not statistically separated",
    );
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host);
    assert!(
        loaded
            .expect_err("overlapping timing confidence must be rejected")
            .to_string()
            .contains("not statistically separated"),
        "autoroute cache load must not trust a selected backend whose timing interval overlaps a competing route"
    );

    std::fs::remove_file(&path).ok(); // LAW10: best-effort cleanup remove; absence/failure is the desired post-state, recall-irrelevant
}
