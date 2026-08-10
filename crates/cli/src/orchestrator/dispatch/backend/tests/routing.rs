use super::super::workload::decode_workload_sketch as decode_workload_sketch_with_plan;
use super::super::workload::workload_key as workload_key_with_plan;
use super::fixtures::workload_key;
use super::*;

#[test]
fn issue32_async_gpu_evidence_requires_complete_depth_matrix_and_preserves_aggregate_caps() {
    let mut timings = Vec::new();
    for backend in [ScanBackend::CpuFallback, ScanBackend::GpuWgpu] {
        let depths: &[u8] = if backend.is_gpu() {
            &[1, 2, 3, 4]
        } else {
            &[1]
        };
        for depth in depths {
            for plain in [false, true] {
                for keyword in [false, true] {
                    let route = MeasuredRoute {
                        backend,
                        phase2_plain_localizer: plain,
                        phase2_keyword_localizer: keyword,
                        gpu_pipeline_depth: *depth,
                    };
                    let timing = BackendTimingEvidence::constant_ms(
                        if backend.is_gpu() {
                            20 - u128::from(*depth)
                        } else {
                            100
                        },
                        AUTOROUTE_CALIBRATION_TRIALS,
                    );
                    let peer = backend.is_gpu().then(|| "test-async-wgpu".to_string());
                    let pipeline = backend.is_gpu().then(|| {
                        (
                            "async-submit-retire".to_string(),
                            1_200_u64 / u64::from(*depth),
                            120_000_u32 / u32::from(*depth),
                        )
                    });
                    timings.push(RouteTimingEvidence::new_with_peer_identity(
                        route, timing, peer, pipeline,
                    ));
                }
            }
        }
    }
    let mut decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::CpuFallback,
        1,
        1,
        test_measurement_shape_evidence(1, 1),
        0xA11D,
        1,
        timings,
        false,
        false,
    );
    let selected = decision
        .resolved_routing_route()
        .expect("complete depth evidence resolves a route");
    decision.backend = selected.backend.label().to_string();
    decision.phase2_plain_localizer = selected.phase2_plain_localizer;
    decision.phase2_keyword_localizer = selected.phase2_keyword_localizer;
    decision.gpu_pipeline_depth = selected.gpu_pipeline_depth;
    let expected = [ScanBackend::CpuFallback, ScanBackend::GpuWgpu]
        .into_iter()
        .map(|backend| backend.label().to_string())
        .collect();
    super::store::validate_decision_route_evidence(&decision, &expected)
        .expect("complete async depth matrix is valid");

    let mut incomplete = decision.clone();
    incomplete
        .primary_point_mut()
        .route_timings
        .retain(|entry| entry.gpu_pipeline_depth != 4);
    let error = super::store::validate_decision_route_evidence(&incomplete, &expected)
        .expect_err("missing eligible depth evidence must fail closed");
    assert!(
        error.to_string().contains("backend/depth census"),
        "incomplete-depth diagnostic must name the missing matrix: {error}"
    );
}

#[test]
fn eligible_backend_labels_use_the_simd_plan_without_materializing_it() {
    let scanner = phase1_test_scanner();
    assert!(!scanner.simd_backend_initialized());
    let labels = super::super::eligible_backend_labels(&scanner, false);
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

/// `sole_compiled_backend` must short-circuit autoroute to the lone backend on a
/// build that compiled no backend choice (portable: no `simd`/`gpu`), and defer to
/// autoroute (return `None`) whenever a real choice exists. This is what keeps a
/// portable single-backend build from failing closed (exit 2) on an uncalibrated
/// workload (the Docker `musl` integration matrix is the end-to-end proof).
#[test]
fn sole_compiled_backend_tracks_the_feature_set() {
    let sole = super::super::sole_compiled_backend();
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
fn a_rejected_cache_is_never_reported_as_an_uncalibrated_bucket() {
    // These two misses call for opposite repairs. A rejected cache does not
    // belong to this binary, host, corpus or config, so recalibrating one
    // bucket into it changes nothing; an absent bucket means the cache is valid
    // and simply does not cover this workload yet. Before the causes were
    // separated both surfaced as the same scalar recovery, which is how a cache
    // that could never hit looked exactly like a corpus nobody had calibrated.
    let path = Some(std::path::PathBuf::from("/tmp/autoroute.json"));
    let rejected = Some("executable digest mismatch".to_string());

    assert_eq!(
        lookup_miss_cause(&path, &rejected, false),
        AutorouteCacheMiss::CacheRejected
    );
    assert_eq!(
        lookup_miss_cause(&path, &rejected, true),
        AutorouteCacheMiss::CacheRejected,
        "a rejected cache stays rejected even when it happens to hold the bucket"
    );
    assert_eq!(
        lookup_miss_cause(&path, &None, false),
        AutorouteCacheMiss::BucketAbsent
    );
    assert_eq!(
        lookup_miss_cause(&path, &None, true),
        AutorouteCacheMiss::RuntimeClassUnproved,
        "a present bucket without runtime-class evidence is not an absent bucket"
    );
    assert_eq!(
        lookup_miss_cause(&None, &None, false),
        AutorouteCacheMiss::NoCacheConfigured
    );
}

#[test]
fn policy_specific_scanner_plans_share_one_cache_corpus_identity() {
    let base_detectors = phase1_test_detectors();
    let base_scanner = CompiledScanner::compile_with_gpu_policy(
        base_detectors.clone(),
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    )
    .expect("compile base scanner");
    let mut policy_detectors = base_detectors;
    policy_detectors[0].min_confidence = Some(0.99);
    let policy_scanner = CompiledScanner::compile_with_gpu_policy(
        policy_detectors,
        keyhog_scanner::GpuInitPolicy::ForceDisabled,
    )
    .expect("compile policy scanner");
    assert_ne!(
        base_scanner.runtime_status().detector_digest,
        policy_scanner.runtime_status().detector_digest,
        "fixture must exercise distinct resolved scanner identities"
    );

    let base_router = MeasuredBackendRouter::new(
        test_hw_caps(),
        base_scanner.runtime_status().pattern_count,
        test_rules_digest().to_string(),
        1,
        false,
        false,
        false,
        Ok(None),
        None,
        &base_scanner,
    );
    let policy_router = MeasuredBackendRouter::new(
        test_hw_caps(),
        policy_scanner.runtime_status().pattern_count,
        test_rules_digest().to_string(),
        2,
        false,
        false,
        false,
        Ok(None),
        None,
        &policy_scanner,
    );
    assert_eq!(
        base_router.detector_digest, policy_router.detector_digest,
        "resolved policies must coexist beneath one canonical cache corpus"
    );
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
        decode_workload_sketch_with_plan(&batch, disabled.clone()),
        DecodeAdmissionSketch::NONE,
        "disabled decode must neither consume sample budget nor project work"
    );
    let key = workload_key_with_plan(
        &batch,
        902,
        all_admitted_phase1(&batch),
        keyhog_scanner::Phase2KeywordTriggerSummary::default(),
        disabled,
    )
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
        decode_workload_sketch_with_plan(&batch[..1], over_limit),
        DecodeAdmissionSketch::NONE,
        "chunks the scanner cannot decode must not project decoder work"
    );
}

/// Raising the floor must not move a single existing decision.
///
/// The residual budget feeds `extra_bytes`, which feeds every chunk's quota,
/// which feeds the sketch, which feeds the workload key that persisted
/// autoroute decisions are stored under. Any change for a batch that already
/// fit would silently invalidate every calibrated cache in the field, so the
/// budget must be exactly the old constant right up to the boundary.
#[test]
fn the_sample_budget_is_unchanged_for_every_batch_that_already_fit() {
    for base in [0usize, 1, 72, 4_096, 64 * 1024 - 1, 64 * 1024] {
        assert_eq!(
            super::super::workload::decode_sample_budget_for_test(base),
            64 * 1024,
            "a batch whose floors need {base} bytes must keep the original budget"
        );
    }
    for base in [64 * 1024 + 1, 786_432] {
        assert_eq!(
            super::super::workload::decode_sample_budget_for_test(base),
            base,
            "a batch whose floors exceed the residual budget samples exactly its floors"
        );
    }
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
    let representative_buckets = crate::orchestrator_config::fused_batch_calibration_counts()
        .into_iter()
        .map(|count| {
            (
                autoroute_stable_bucket(count as u64),
                autoroute_stable_bucket((count * 4 * 1024) as u64),
            )
        })
        .collect::<HashSet<_>>();

    assert_eq!(
        crate::orchestrator_config::FUSED_BATCH_DEFAULT,
        1024,
        "tiny-file dispatch and install-time representatives must change together"
    );
    for count in 1..=crate::orchestrator_config::FUSED_BATCH_DEFAULT {
        let buckets = (
            autoroute_stable_bucket(count as u64),
            autoroute_stable_bucket((count * 4 * 1024) as u64),
        );
        assert!(
            representative_buckets.contains(&buckets),
            "install calibration representatives must cover {count} x 4 KiB residual fused batch buckets {buckets:?}"
        );
    }
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
fn issue32_autoroute_cache_roundtrip_and_digest_invalidation() {
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
                None,
                Some(timing(gpu_ms)),
                Some(timing(localizer_ms)),
                Some(timing(localizer_ms + 8)),
                None,
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
    let parsed: serde_json::Value =
        serde_json::from_str(&serialized).expect("parse autoroute cache JSON");
    assert_eq!(
        parsed.get("version").and_then(serde_json::Value::as_u64),
        Some(AUTOROUTE_CACHE_VERSION as u64)
    );
    for required in [
        "\"build_features\"",
        "\"cli_features\"",
        "\"scanner_features\"",
        "\"sources_features\"",
        "\"verifier_features\"",
        "\"executable_sha256\"",
        "\"rules_digest\"",
        "\"cpu_model\"",
        "\"physical_cores\"",
        "\"logical_cores\"",
        "\"total_memory_mb\"",
        "\"hyperscan_runtime_identity\"",
        "\"gpu_runtime_backend\"",
        "\"gpu_driver_runtime_identity\"",
        "\"gpu_batch_input_limit_bytes\"",
        "\"decode_kind_mask\"",
        "\"decode_candidate_count_bucket\"",
        "\"decode_candidate_bytes_bucket\"",
        "\"decode_unknown\"",
        "\"candidate_receipts\"",
        "\"phase2_plain_localizer\":true",
        "\"phase2_keyword_localizer\":false",
        "\"gpu_pipeline_depth\":1",
        "\"gpu_dispatch_capability\"",
        "\"gpu_slot_input_capacity_bytes\"",
        "\"gpu_slot_match_capacity\"",
        "\"correctness_digest\"",
        "\"completed_trials\"",
        "\"evidence_digest\"",
        "\"calibrated_at_unix_ms\"",
        "\"route_timings\"",
        "\"trials_ns\"",
    ] {
        assert!(
            serialized.contains(required),
            "cache JSON is missing required primary evidence field {required}"
        );
    }
    let stale_without_depth = serialized.replacen("\"gpu_pipeline_depth\":1,", "", 1);
    let stale_error = serde_json::from_str::<AutorouteCache>(&stale_without_depth)
        .expect_err("missing calibrated pipeline depth must reject stale evidence");
    assert!(
        stale_error.to_string().contains("gpu_pipeline_depth"),
        "stale depth diagnostic must name the missing route dimension: {stale_error}"
    );
    for derived in [
        "\"decode_density_bucket\"",
        "\"simd_timing\"",
        "\"confidence_interval_95_ns\"",
        "\"best_ns\"",
        "\"mean_ns\"",
    ] {
        assert!(
            !serialized.contains(derived),
            "cache JSON persisted derived field {derived}"
        );
    }
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
fn exact_peer_tie_selects_the_lower_complexity_backend_deterministically() {
    let dir = tempfile::TempDir::new().expect("tempdir for tie calibration");
    let path = dir.path().join("tie-autoroute-cache.json");
    let digest = 0x0FF1_CE00_0FF1_CE00u64;
    let config_digest = 0xD1CE_D1CE_D1CE_D1CEu64;
    let host = test_host(Some("NVIDIA GeForce RTX 5090"));
    let key = test_workload_key();

    // SimdCpu and the GPU route measure identically (20ms). Neither peer is
    // proven faster, so the stable lower-complexity route wins.
    let tie_to_simd =
        AutorouteDecision::new(ScanBackend::SimdCpu, 8 * 1024 * 1024, 1, 20, None, Some(20));
    assert_eq!(
        tie_to_simd.resolved_routing_backend(),
        Some(ScanBackend::SimdCpu),
        "an exact peer tie must resolve deterministically without preferring GPU complexity"
    );
    let mut decisions = HashMap::new();
    decisions.insert(key.clone(), tie_to_simd);
    save_autoroute_cache(
        &path,
        digest,
        test_rules_digest(),
        config_digest,
        &host,
        &decisions,
    )
    .expect("a non-inferior deterministic tie decision must persist");
    let loaded = load_autoroute_cache(&path, digest, test_rules_digest(), config_digest, &host)
        .expect("the deterministic tie decision must reload");
    assert_eq!(
        loaded.get(&key).and_then(AutorouteDecision::backend),
        Some(ScanBackend::SimdCpu)
    );
}

#[test]
fn same_backend_tie_with_overlapping_peer_uses_noninferior_compiled_default() {
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
            None,
            Some(timing(10)),
            Some(timing(10)),
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
        "an exact overlap must select the lower-complexity backend's compiled default"
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
            None,
            Some(timing(10_000)),
            Some(timing(10)),
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
                        gpu_pipeline_depth: 1,
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
            gpu_pipeline_depth: 1,
        }),
        "a tied nondefault leader must resolve deterministically without claiming an exact winner"
    );
    assert_eq!(
        decision.resolved_recovery_route(ScanBackend::SimdCpu, true),
        Some(MeasuredRoute {
            backend: ScanBackend::CpuFallback,
            phase2_plain_localizer: false,
            phase2_keyword_localizer: true,
            gpu_pipeline_depth: 1,
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
                        gpu_pipeline_depth: 1,
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

    assert!(
        !decision.has_confidence_supported_route(),
        "paired rounds must not replace the independent cross-backend confidence interval"
    );
    assert_eq!(
        decision.resolved_routing_route(),
        Some(MeasuredRoute {
            backend: ScanBackend::CpuFallback,
            phase2_plain_localizer: false,
            phase2_keyword_localizer: true,
            gpu_pipeline_depth: 1,
        }),
        "an unproved measurement resolves to the lowest-complexity backend's compiled default"
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
            None,
            Some(timing(15)),
            Some(timing(40)),
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
            backend: ScanBackend::SimdCpu,
            phase2_plain_localizer: false,
            phase2_keyword_localizer: false,
            gpu_pipeline_depth: 1,
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
    assert!(error.contains("changes its confidence-supported remaining one-shot recovery backend"));
}

#[test]
fn overlapping_confidence_resolves_the_lower_complexity_backend() {
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
        Some(ScanBackend::SimdCpu),
        "a 1 ms unproved GPU lead inside the GPU's own upper bound does not buy GPU bring-up"
    );
}

#[test]
fn a_measurably_worse_median_cannot_win_a_dead_heat_on_a_wide_error_bar() {
    // Scalar is far slower on average but jitters enough that its interval
    // still overlaps the accelerator's. Lower complexity must not rescue it.
    let cpu_timing = BackendTimingEvidence::from_trial_ns(vec![
        1_000_000,
        60_000_000,
        60_000_000,
        60_000_000,
        60_000_000,
        60_000_000,
        200_000_000,
    ])
    .expect("valid CPU timing");
    let simd_timing = BackendTimingEvidence::from_trial_ns(vec![
        21_000_000, 20_000_000, 20_000_000, 20_000_000, 22_000_000, 24_000_000, 26_000_000,
    ])
    .expect("valid SIMD timing");
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
        !decision.has_confidence_supported_route(),
        "fixture must retain overlapping 95% confidence intervals"
    );
    assert_eq!(
        decision.resolved_routing_backend(),
        Some(ScanBackend::SimdCpu),
        "a scalar median outside the fastest route's own 95% bound is ineligible"
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

#[test]
fn issue32_autoroute_cache_rejects_stale_v53_before_payload_decode() {
    let dir = tempfile::tempdir().expect("v53 autoroute cache tempdir");
    let path = dir.path().join("autoroute.json");
    std::fs::write(&path, br#"{"version":53}"#).expect("write stale v53 cache");
    let error = load_autoroute_cache(
        &path,
        0x1234_5678_9ABC_DEF0,
        test_rules_digest(),
        0xA55A_D00D_CAFE_BEEF,
        &test_host(None),
    )
    .expect_err("v53 cache must be rejected before payload decode")
    .to_string();
    assert!(
        error.contains("unsupported autoroute cache version 53")
            && error.contains("expects 54")
            && !error.contains("missing field"),
        "v53 rejection must be version-first and actionable: {error}"
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
    let observer = Arc::new(Mutex::new(BTreeSet::from([AutorouteMeasurementReceipt {
        config_digest: "a55ad00dcafebeef".to_string(),
        host_identity: host_identity_digest(&host),
        workload: render_workload_key(&key),
        measurement_shape_digest: "superseded-shape".to_string(),
    }])));
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
        "the receipt must replace superseded evidence and carry the exact host, workload, and measurement shape that were persisted"
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
    stable
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
        .expect("an unseparated point that still names the class backend joins the class");
    assert_eq!(stable.calibration_points.len(), 3);
    assert_eq!(
        stable.resolved_routing_backend(),
        Some(ScanBackend::SimdCpu)
    );
    assert!(
        !stable.has_confidence_supported_route(),
        "an unseparated point must cost the class its separated proof, not its route"
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
    assert!(error.contains("changes its confidence-supported backend across measured points"));
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
    let hit_admission = scanner.phase1_admission_plan(&hit_batch);
    let hit_key = workload_key_with_plan(
        &hit_batch,
        pattern_count,
        hit_admission.summary(),
        hit_admission.phase2_keyword_triggers(),
        test_decode_workload_plan(),
    )
    .expect("hit workload classified");
    let miss_batch = vec![test_chunk_with_source(
        "token = abc\n".repeat(4096),
        "filesystem",
    )];
    let miss_admission = scanner.phase1_admission_plan(&miss_batch);
    let miss_key = workload_key_with_plan(
        &miss_batch,
        pattern_count,
        miss_admission.summary(),
        miss_admission.phase2_keyword_triggers(),
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
        autoroute_detector_digest(test_rules_digest()),
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
    let hit = router
        .choose_with_plan(&scanner, None, &hit_batch)
        .expect("cache hit should choose persisted backend");
    assert_eq!(
        hit.backend,
        if scanner.simd_backend_available() {
            ScanBackend::SimdCpu
        } else {
            ScanBackend::CpuFallback
        },
        "cache-hit recovery was unexpected: {:?}",
        hit.autoroute_recovery
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
        super::super::evidence::BackendTimingEvidence::from_trial_ns(Vec::new()).is_none(),
        "autoroute timing evidence must not convert an empty trial set into a zero-duration route"
    );
}

#[test]
fn immutable_gpu_preparation_costs_change_only_the_cold_trial() {
    let literal_preparation_ns = 60;
    let phase2_preparation_ns = 30;
    let evidence = super::super::evidence::BackendTimingEvidence::from_trial_ns(vec![
        10, 20, 20, 20, 20, 20, 20,
    ])
    .expect("timing evidence")
    .add_to_first_trial(literal_preparation_ns + phase2_preparation_ns);
    assert_eq!(evidence.trials_ns, vec![100, 20, 20, 20, 20, 20, 20]);
    let (cold_ns, warm, one_shot_ns) =
        super::super::evidence::gpu_cold_warm_route_evidence(&evidence).expect("cold/warm split");
    assert_eq!(cold_ns, 100);
    assert_eq!(warm.median_ns(), 20);
    assert_eq!(one_shot_ns, 100);
}

#[test]
fn calibration_candidate_order_rotates_across_workload_bands() {
    let rotations = [1_u64, 2, 4, 8, 16, 32]
        .into_iter()
        .map(|bytes| super::super::calibration::calibration_candidate_rotation(bytes, 1, 4))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(rotations, [0, 1, 2, 3].into_iter().collect());
}

#[test]
fn autoroute_confidence_uses_student_t_for_small_calibration_samples() {
    let simd_timing = super::super::evidence::BackendTimingEvidence::from_trial_ns(vec![
        90, 95, 100, 100, 100, 105, 110,
    ])
    .expect("SIMD timing evidence");
    let cpu_timing = super::super::evidence::BackendTimingEvidence::from_trial_ns(vec![
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
            std::sync::Arc::from("account"),
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
    trial_match.companions.insert(
        std::sync::Arc::from("account"),
        "staging@example.test".to_string(),
    );
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
    changed.companions.insert(
        std::sync::Arc::from("account"),
        "sensitive-companion".to_string(),
    );
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
    host.eligible_backends
        .push(ScanBackend::GpuMetal.label().to_string());
    host.eligible_backends.sort_unstable();
    let key = test_workload_key();
    let complete = valid_decision_for_host(&host);

    for backend in [
        ScanBackend::GpuCuda,
        ScanBackend::GpuMetal,
        ScanBackend::GpuWgpu,
    ] {
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
        super::super::evidence::gpu_cold_warm_route_evidence(gpu_timing)
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
        decision_requires_gpu_artifact_identity(&decision),
        "a CPU/SIMD one-shot decision with a GPU persistent route must retain GPU artifact identity"
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

/// Every persisted surface that can cause or prove a GPU route binds installed artifacts.
#[test]
fn gpu_artifact_identity_covers_selected_routes_receipts_and_timing_candidates() {
    let mut decision = cpu_decision(ScanBackend::CpuFallback);
    assert!(!decision_requires_gpu_artifact_identity(&decision));

    decision.backend = ScanBackend::GpuWgpu.label().to_string();
    assert!(decision_requires_gpu_artifact_identity(&decision));
    decision.backend = ScanBackend::CpuFallback.label().to_string();

    let point = decision
        .calibration_points
        .first_mut()
        .expect("CPU fixture calibration point");
    let receipt = point
        .candidate_receipts
        .first_mut()
        .expect("CPU fixture candidate receipt");
    receipt.backend = ScanBackend::GpuWgpu.label().to_string();
    assert!(decision_requires_gpu_artifact_identity(&decision));
    decision.calibration_points[0].candidate_receipts[0].backend =
        ScanBackend::CpuFallback.label().to_string();

    let timing = decision.calibration_points[0]
        .route_timings
        .first_mut()
        .expect("CPU fixture route timing");
    timing.backend = ScanBackend::GpuWgpu.label().to_string();
    assert!(decision_requires_gpu_artifact_identity(&decision));
}

#[test]
fn persistent_daemon_keeps_one_shot_route_when_warm_peer_is_not_proven_faster() {
    let simd = BackendTimingEvidence::from_trial_ns(vec![
        100_000_000,
        18_000_000,
        22_000_000,
        19_000_000,
        21_000_000,
        18_500_000,
        21_500_000,
    ])
    .expect("SIMD cold/warm timing evidence");
    let cpu =
        BackendTimingEvidence::from_trial_ns(vec![20_000_000; 7]).expect("CPU timing evidence");
    let decision = AutorouteDecision::from_timing_evidence(
        ScanBackend::CpuFallback,
        1,
        1,
        0xC01D,
        1,
        simd,
        Some(cpu),
        None,
    );

    assert_eq!(
        decision.resolved_routing_backend(),
        Some(ScanBackend::CpuFallback),
        "cold Hyperscan materialization makes CPU the proven one-shot route"
    );
    assert_eq!(
        decision.primary_point().resolve_measured_route(true),
        None,
        "the fixture must exercise the non-inferior one-shot fallback rather than an exact warm winner"
    );
    assert_eq!(
        decision.resolved_persistent_backend(),
        Some(ScanBackend::CpuFallback),
        "overlapping warm evidence must retain the proven route instead of making calibration unusable"
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
                None,
                Some(timing(16)),
                Some(timing(1_030)),
                Some(timing(1_040)),
                Some(timing(1_008)),
                None,
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
fn daemon_without_valid_autoroute_evidence_initializes_required_recovery() {
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

    let expected_routes = if autoroute_required() {
        vec![ScanBackend::CpuFallback]
    } else {
        Vec::new()
    };

    assert_eq!(
        router
            .persistent_routes()
            .expect("invalid autoroute state must not prevent daemon readiness"),
        expected_routes,
        "daemon readiness must initialize scalar recovery exactly when autoroute is required"
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
    let timing =
        |ms| BackendTimingEvidence::constant_ms(ms, super::super::AUTOROUTE_CALIBRATION_TRIALS);
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
            None,
            Some(timing(15)),
            Some(timing(1_030)),
            Some(timing(1_040)),
            Some(timing(1_010)),
            None,
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
            None,
            Some(timing(9)),
            Some(timing(1_030)),
            Some(timing(1_040)),
            Some(timing(1_016)),
            None,
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
            None,
            Some(timing(8)),
            Some(timing(20)),
            None,
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
        None,
        Some(timing(40)),
        Some(timing(50)),
        None,
        None,
        None,
    );
    let keyword_route = MeasuredRoute {
        backend: ScanBackend::SimdCpu,
        phase2_plain_localizer: false,
        phase2_keyword_localizer: true,
        gpu_pipeline_depth: 1,
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

/// Proves that live calibration times both physical GPU implementations before
/// resolving a route; this must run only on a host with working CUDA and WGPU.
#[cfg(feature = "default")]
#[test]
#[ignore = "GPU-host gate; run explicitly with --ignored on a host with live CUDA and WGPU"]
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
        "CUDA peer must be live on the GPU release host: {candidates:#?}"
    );
    assert!(
        candidates
            .iter()
            .find(|candidate| candidate.backend == ScanBackend::GpuWgpu)
            .is_some_and(|candidate| candidate.available),
        "WGPU peer must be live on the GPU release host: {candidates:#?}"
    );
    let sample = vec![Chunk {
        data: "key=KHGPUCAL_A1b2C3d4E5f6G7h8I9j0\n".repeat(1024).into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    }];
    let eligible = super::super::eligible_backend_labels(&scanner, true);
    let admission_plan = scanner.phase1_admission_plan(&sample);
    let outcome = super::super::calibration::calibrate_fastest_correct_backend(
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
                diagnostic.contains("calibration timing does not resolve one route")
                    && diagnostic.contains(ScanBackend::GpuCuda.label())
                    && diagnostic.contains(ScanBackend::GpuWgpu.label())
                    && diagnostic.contains("median_ns=")
                    && diagnostic.contains("ci95_ns=["),
                "an honest refusal must prove that both live GPU peers were measured and expose why no winner exists: {diagnostic}"
            );
        }
    }
}

// --- Same-backend execution-plan stability ---------------------------------
//
// Calibrating the mirror corpus five times with an identical binary, corpus
// and host, the same 664,161-byte/4,096-chunk point resolved
// `plain=true+keyword=true` on three runs and `false+false` on two, and the
// merge check then rejected the whole calibration as a workload crossover.
// Two of those five runs disagreed in OPPOSITE directions on that one point,
// which is the proof the verdict was noise: `cpu-fallback` won every time and
// only the sub-plan flipped. Three of five runs therefore persisted nothing,
// and every later scan of that workload paid scalar recovery.
//
// A paired 95% test can call a winner while the two intervals overlap almost
// entirely, and on the next sample it calls the other one. These contracts pin
// the rule that stops that: on one backend, a plan wins only when its interval
// clears the other's as well.

/// Trials that rise together, one consistently a hair faster.
///
/// The paired test sees a uniform sign and declares a winner; the intervals
/// overlap almost completely, so the lead is inside the noise. This is the
/// exact shape that made calibration flip run to run.
fn overlapping_paired_trials(offset_ns: u128) -> BackendTimingEvidence {
    let trials = (1..=AUTOROUTE_CALIBRATION_TRIALS)
        .map(|round| (round as u128) * 100_000_000 + offset_ns)
        .collect::<Vec<_>>();
    BackendTimingEvidence::from_trial_ns(trials).expect("valid trial evidence")
}

fn scalar_plan_decision(
    sample_bytes: u64,
    faster_plan: (bool, bool),
    compiled_default: (bool, bool),
) -> AutorouteDecision {
    // A far slower accelerator peer, so the scalar routes are compared the way
    // they are in a real calibration: cpu-fallback clearly wins the backend,
    // and the only open question is which execution plan it runs.
    let mut route_timings = vec![RouteTimingEvidence::new(
        MeasuredRoute {
            backend: ScanBackend::SimdCpu,
            phase2_plain_localizer: false,
            phase2_keyword_localizer: false,
            gpu_pipeline_depth: 1,
        },
        BackendTimingEvidence::constant_ms(50_000, AUTOROUTE_CALIBRATION_TRIALS),
    )];
    route_timings.extend(
        [(false, false), (true, true)]
            .into_iter()
            .map(|(plain, keyword)| {
                let offset = if (plain, keyword) == faster_plan {
                    0
                } else {
                    1_000_000
                };
                RouteTimingEvidence::new(
                    MeasuredRoute {
                        backend: ScanBackend::CpuFallback,
                        phase2_plain_localizer: plain,
                        phase2_keyword_localizer: keyword,
                        gpu_pipeline_depth: 1,
                    },
                    overlapping_paired_trials(offset),
                )
            }),
    );
    let mut decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::CpuFallback,
        sample_bytes,
        1,
        test_measurement_shape_evidence(sample_bytes, 1),
        0x5A17_D0C5_5A17_D0C5,
        1,
        route_timings,
        compiled_default.0,
        compiled_default.1,
    );
    // Calibration declares the route it resolved before the point is merged
    // (see `calibrate_workload_backend`), so the fixture must too.
    let resolved = decision
        .resolved_routing_route()
        .expect("fixture evidence resolves one route");
    decision.backend = resolved.backend.label().to_string();
    decision.phase2_plain_localizer = resolved.phase2_plain_localizer;
    decision.phase2_keyword_localizer = resolved.phase2_keyword_localizer;
    decision
}

/// A lead that does not clear its own error bars must not decide the plan.
///
/// Both orderings of the same overlapping measurement have to resolve to the
/// compiled default. If either one instead followed the paired winner, the
/// persisted plan would depend on which way the noise fell, which is what made
/// three of five identical calibration runs persist nothing at all.
#[test]
fn an_overlapping_plan_lead_resolves_to_the_compiled_default_either_way() {
    for faster_plan in [(false, false), (true, true)] {
        let decision = scalar_plan_decision(8 * 1024 * 1024, faster_plan, (true, true));
        let resolved = decision
            .resolved_routing_route()
            .expect("an overlapping same-backend plan pair still resolves one route");
        assert_eq!(resolved.backend, ScanBackend::CpuFallback);
        assert!(
            resolved.phase2_plain_localizer && resolved.phase2_keyword_localizer,
            "noise favouring {faster_plan:?} must not move the plan off the compiled default"
        );
    }
}

/// The same holds when the build's default is the other plan.
///
/// Pinning only one default would let the rule pass by accident on a build
/// whose default happened to match the tie-break's fallback ordering.
#[test]
fn an_overlapping_plan_lead_honours_whichever_plan_the_build_defaults_to() {
    for faster_plan in [(false, false), (true, true)] {
        let decision = scalar_plan_decision(8 * 1024 * 1024, faster_plan, (false, false));
        let resolved = decision
            .resolved_routing_route()
            .expect("an overlapping same-backend plan pair still resolves one route");
        assert!(
            !resolved.phase2_plain_localizer && !resolved.phase2_keyword_localizer,
            "noise favouring {faster_plan:?} must not move the plan off the compiled default"
        );
    }
}

/// Two points measuring the same class must merge, whichever way the noise fell.
///
/// This is the end of the chain that failed in the field: each point resolved
/// its own plan from an overlapping lead, the points disagreed, and
/// `merge_calibration_point` rejected the entire calibration with advice to
/// split the workload identity, which could never have fixed a verdict that
/// flips on identical input.
#[test]
fn points_whose_plan_leads_are_noise_merge_into_one_envelope() {
    let mut envelope = scalar_plan_decision(8 * 1024 * 1024, (true, true), (true, true));
    envelope
        .merge_calibration_point(scalar_plan_decision(
            12 * 1024 * 1024,
            (false, false),
            (true, true),
        ))
        .expect("points that disagree only inside the noise must form one envelope");
    assert_eq!(envelope.calibration_points.len(), 2);
    let resolved = envelope
        .resolved_routing_route()
        .expect("the merged class resolves one route");
    assert_eq!(resolved.backend, ScanBackend::CpuFallback);
    assert!(resolved.phase2_plain_localizer && resolved.phase2_keyword_localizer);
}

/// A plan lead that DOES clear its error bars still decides the plan.
///
/// The rule raises the evidence bar; it must not become a blanket preference
/// for the compiled default. A plan that is genuinely, separably faster has to
/// win, or calibration would stop finding the fastest execution plan at all.
#[test]
fn a_separated_plan_lead_still_beats_the_compiled_default() {
    let route_timings = [(false, false), (true, true)]
        .into_iter()
        .map(|(plain, keyword)| {
            let ms = if (plain, keyword) == (false, false) {
                10
            } else {
                90
            };
            RouteTimingEvidence::new(
                MeasuredRoute {
                    backend: ScanBackend::CpuFallback,
                    phase2_plain_localizer: plain,
                    phase2_keyword_localizer: keyword,
                    gpu_pipeline_depth: 1,
                },
                BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS),
            )
        })
        .collect::<Vec<_>>();
    let decision = AutorouteDecision::from_peer_timing_evidence(
        ScanBackend::CpuFallback,
        8 * 1024 * 1024,
        1,
        test_measurement_shape_evidence(8 * 1024 * 1024, 1),
        0x5A17_D0C5_5A17_D0C5,
        1,
        route_timings,
        true,
        true,
    );
    let resolved = decision
        .resolved_routing_route()
        .expect("a separated plan lead resolves");
    assert!(
        !resolved.phase2_plain_localizer && !resolved.phase2_keyword_localizer,
        "a 9x separated lead must beat the compiled default"
    );
}

/// Points that split on the plan after a SEPARATED lead still reconcile to the
/// compiled default rather than discarding the class.
///
/// Interval separation cut the mirror corpus's failure rate from three runs in
/// five to one in ten, but did not reach zero: with seven trials a 95% interval
/// can separate by luck. Whatever the cause, two points that agree the backend
/// is `cpu-fallback` have settled the question autoroute exists to answer, and
/// throwing that away over a sub-plan leaves the workload paying scalar
/// recovery on every future scan.
#[test]
fn a_split_plan_across_points_reconciles_to_the_compiled_default() {
    let separated =
        |sample_bytes: u64, faster_plan: (bool, bool)| {
            let mut route_timings = vec![RouteTimingEvidence::new(
                MeasuredRoute {
                    backend: ScanBackend::SimdCpu,
                    phase2_plain_localizer: false,
                    phase2_keyword_localizer: false,
                    gpu_pipeline_depth: 1,
                },
                BackendTimingEvidence::constant_ms(50_000, AUTOROUTE_CALIBRATION_TRIALS),
            )];
            route_timings.extend([(false, false), (true, true)].into_iter().map(
                |(plain, keyword)| {
                    let ms = if (plain, keyword) == faster_plan {
                        10
                    } else {
                        90
                    };
                    RouteTimingEvidence::new(
                        MeasuredRoute {
                            backend: ScanBackend::CpuFallback,
                            phase2_plain_localizer: plain,
                            phase2_keyword_localizer: keyword,
                            gpu_pipeline_depth: 1,
                        },
                        BackendTimingEvidence::constant_ms(ms, AUTOROUTE_CALIBRATION_TRIALS),
                    )
                },
            ));
            let mut decision = AutorouteDecision::from_peer_timing_evidence(
                ScanBackend::CpuFallback,
                sample_bytes,
                1,
                test_measurement_shape_evidence(sample_bytes, 1),
                0x5A17_D0C5_5A17_D0C5,
                1,
                route_timings,
                true,
                true,
            );
            let resolved = decision
                .resolved_routing_route()
                .expect("a separated lead resolves");
            decision.backend = resolved.backend.label().to_string();
            decision.phase2_plain_localizer = resolved.phase2_plain_localizer;
            decision.phase2_keyword_localizer = resolved.phase2_keyword_localizer;
            decision
        };

    let mut envelope = separated(8 * 1024 * 1024, (true, true));
    envelope
        .merge_calibration_point(separated(12 * 1024 * 1024, (false, false)))
        .expect("points agreeing on the backend must not discard the class");
    let resolved = envelope
        .resolved_routing_route()
        .expect("the class reconciles to one route");
    assert_eq!(resolved.backend, ScanBackend::CpuFallback);
    assert!(
        resolved.phase2_plain_localizer && resolved.phase2_keyword_localizer,
        "a split plan must land on the compiled default, not on either point's pick"
    );
}

/// A genuine BACKEND crossover is still refused.
///
/// Reconciling the execution plan must not soften the thing autoroute actually
/// selects. If two points disagree about which backend is fastest, the class is
/// unresolved and must stay that way.
#[test]
fn a_backend_crossover_across_points_still_refuses_to_resolve() {
    let winner = |sample_bytes: u64, cpu_ms: u128, simd_ms: u128| {
        let route_timings = vec![
            RouteTimingEvidence::new(
                MeasuredRoute {
                    backend: ScanBackend::SimdCpu,
                    phase2_plain_localizer: false,
                    phase2_keyword_localizer: false,
                    gpu_pipeline_depth: 1,
                },
                BackendTimingEvidence::constant_ms(simd_ms, AUTOROUTE_CALIBRATION_TRIALS),
            ),
            RouteTimingEvidence::new(
                MeasuredRoute {
                    backend: ScanBackend::CpuFallback,
                    phase2_plain_localizer: true,
                    phase2_keyword_localizer: true,
                    gpu_pipeline_depth: 1,
                },
                BackendTimingEvidence::constant_ms(cpu_ms, AUTOROUTE_CALIBRATION_TRIALS),
            ),
        ];
        AutorouteDecision::from_peer_timing_evidence(
            ScanBackend::CpuFallback,
            sample_bytes,
            1,
            test_measurement_shape_evidence(sample_bytes, 1),
            0x5A17_D0C5_5A17_D0C5,
            1,
            route_timings,
            true,
            true,
        )
    };
    let mut envelope = winner(8 * 1024 * 1024, 10, 900);
    envelope.calibration_points.push(
        winner(12 * 1024 * 1024, 900, 10)
            .calibration_points
            .remove(0),
    );
    assert_eq!(
        envelope.resolved_routing_route(),
        None,
        "points that disagree about the backend must leave the class unresolved"
    );
}

/// A merge that moves the class's plan must move the DECLARED plan with it.
///
/// Validation requires the persisted backend and localizer fields to equal what
/// `resolved_routing_route` computes from the timing evidence. Reconciling a
/// split plan onto the compiled default changes that answer, so a merge that
/// left the first point's plan declared produced a cache that failed its own
/// validation with "selected route is not supported by the persisted timing
/// evidence" - one calibration run in ten on the mirror corpus.
#[test]
fn merging_a_point_redeclares_the_reconciled_route() {
    let mut envelope = scalar_plan_decision(8 * 1024 * 1024, (false, false), (true, true));
    envelope.backend = ScanBackend::CpuFallback.label().to_string();
    envelope.phase2_plain_localizer = false;
    envelope.phase2_keyword_localizer = false;

    envelope
        .merge_calibration_point(scalar_plan_decision(
            12 * 1024 * 1024,
            (true, true),
            (true, true),
        ))
        .expect("the points agree on the backend");

    let resolved = envelope
        .resolved_routing_route()
        .expect("the merged class resolves one route");
    assert_eq!(
        (
            envelope.backend.as_str(),
            envelope.phase2_plain_localizer,
            envelope.phase2_keyword_localizer
        ),
        (
            resolved.backend.label(),
            resolved.phase2_plain_localizer,
            resolved.phase2_keyword_localizer
        ),
        "the declared route must equal the route the evidence resolves"
    );
}

/// Regression: autoroute binds only installer-owned GPU artifacts. Runtime cache
/// growth is irrelevant, while any named artifact or manifest mutation fails closed.
#[test]
fn installed_gpu_artifact_identity_tracks_exact_manifest_members() {
    use sha2::Digest as _;

    let directory = tempfile::tempdir().expect("create GPU artifact directory");
    let artifact = directory.path().join("installed.bin");
    std::fs::write(&artifact, b"installed-v1").expect("write installed GPU artifact");
    let sha256 = format!("{:x}", sha2::Sha256::digest(b"installed-v1"));
    let manifest = serde_json::json!({
        "version": 1,
        "artifacts": [{"file_name": "installed.bin", "sha256": sha256}],
    });
    std::fs::write(
        directory.path().join(".installed_manifest.json"),
        serde_json::to_vec(&manifest).expect("serialize manifest"),
    )
    .expect("write installed manifest");

    let identity =
        installed_gpu_sidecar_digest(directory.path()).expect("valid installed identity");
    std::fs::write(
        directory.path().join("lazy-unrelated.bin"),
        b"runtime-cache",
    )
    .expect("write unrelated runtime cache blob");
    assert_eq!(
        installed_gpu_sidecar_digest(directory.path()).as_deref(),
        Some(identity.as_str()),
        "unrelated lazy cache entries must not invalidate calibrated artifacts"
    );

    std::fs::write(&artifact, b"installed-v2").expect("mutate installed artifact");
    assert!(
        installed_gpu_sidecar_digest(directory.path()).is_none(),
        "a named artifact mutation must invalidate calibration identity"
    );

    std::fs::write(&artifact, b"installed-v1").expect("restore installed artifact");
    let duplicate_manifest = serde_json::json!({
        "version": 1,
        "artifacts": [
            {"file_name": "installed.bin", "sha256": sha256},
            {"file_name": "installed.bin", "sha256": sha256},
        ],
    });
    std::fs::write(
        directory.path().join(".installed_manifest.json"),
        serde_json::to_vec(&duplicate_manifest).expect("serialize duplicate manifest"),
    )
    .expect("write duplicate manifest");
    assert!(
        installed_gpu_sidecar_digest(directory.path()).is_none(),
        "duplicate manifest members must fail closed"
    );
}

/// Every manifest boundary fails closed before an untrusted member can affect routing.
#[test]
fn installed_gpu_artifact_identity_rejects_invalid_manifests_and_size_limits() {
    let directory = tempfile::tempdir().expect("create GPU artifact directory");
    std::fs::write(directory.path().join("installed.bin"), b"installed")
        .expect("write installed artifact");
    let manifest_path = directory.path().join(".installed_manifest.json");
    let invalid_manifests = [
        serde_json::json!({
            "version": 1,
            "artifacts": [{"file_name": "missing.bin", "sha256": "0".repeat(64)}],
        }),
        serde_json::json!({
            "version": 1,
            "artifacts": [{"file_name": "../installed.bin", "sha256": "0".repeat(64)}],
        }),
        serde_json::json!({
            "version": 1,
            "artifacts": [{"file_name": "installed.bin", "sha256": "z".repeat(64)}],
        }),
        serde_json::json!({
            "version": 1,
            "artifacts": [{"file_name": "installed.bin", "sha256": "0".repeat(64), "extra": true}],
        }),
        serde_json::json!({"version": 2, "artifacts": []}),
    ];
    for manifest in invalid_manifests {
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("serialize invalid manifest"),
        )
        .expect("write invalid manifest");
        assert!(
            installed_gpu_sidecar_digest(directory.path()).is_none(),
            "invalid manifest must not produce an artifact identity: {manifest}"
        );
    }

    let oversized_manifest = std::fs::File::create(&manifest_path).expect("create manifest");
    oversized_manifest
        .set_len(1024 * 1024 + 1)
        .expect("make sparse oversized manifest");
    assert!(installed_gpu_sidecar_digest(directory.path()).is_none());

    let oversized_artifact = directory.path().join("oversized.bin");
    let file = std::fs::File::create(&oversized_artifact).expect("create oversized artifact");
    file.set_len(256 * 1024 * 1024 + 1)
        .expect("make sparse oversized artifact");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "artifacts": [{"file_name": "oversized.bin", "sha256": "0".repeat(64)}],
        }))
        .expect("serialize oversized artifact manifest"),
    )
    .expect("write oversized artifact manifest");
    assert!(installed_gpu_sidecar_digest(directory.path()).is_none());
}

/// Manifest order is presentation only; the same installed set has one identity.
#[test]
fn installed_gpu_artifact_identity_is_order_independent() {
    use sha2::Digest as _;

    let directory = tempfile::tempdir().expect("create GPU artifact directory");
    let digest_a = format!("{:x}", sha2::Sha256::digest(b"a"));
    let digest_b = format!("{:x}", sha2::Sha256::digest(b"b"));
    std::fs::write(directory.path().join("a.bin"), b"a").expect("write a");
    std::fs::write(directory.path().join("b.bin"), b"b").expect("write b");
    let manifest_path = directory.path().join(".installed_manifest.json");
    let entry_a = serde_json::json!({"file_name": "a.bin", "sha256": digest_a});
    let entry_b = serde_json::json!({"file_name": "b.bin", "sha256": digest_b});

    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "artifacts": [entry_b.clone(), entry_a.clone()],
        }))
        .expect("serialize first order"),
    )
    .expect("write first order");
    let first = installed_gpu_sidecar_digest(directory.path()).expect("first identity");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "artifacts": [entry_a, entry_b],
        }))
        .expect("serialize second order"),
    )
    .expect("write second order");
    assert_eq!(
        installed_gpu_sidecar_digest(directory.path()).as_deref(),
        Some(first.as_str())
    );
}

/// A symlinked installed member is not an installer-owned regular file.
#[cfg(unix)]
#[test]
fn installed_gpu_artifact_identity_rejects_symlink_members() {
    use sha2::Digest as _;
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("create GPU artifact directory");
    std::fs::write(directory.path().join("target"), b"artifact").expect("write target");
    symlink("target", directory.path().join("installed.bin")).expect("create member symlink");
    std::fs::write(
        directory.path().join(".installed_manifest.json"),
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "artifacts": [{
                "file_name": "installed.bin",
                "sha256": format!("{:x}", sha2::Sha256::digest(b"artifact")),
            }],
        }))
        .expect("serialize manifest"),
    )
    .expect("write manifest");
    assert!(installed_gpu_sidecar_digest(directory.path()).is_none());
}
