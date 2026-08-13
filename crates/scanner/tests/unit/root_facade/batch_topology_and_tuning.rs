use keyhog_scanner::CompiledScanner;

#[test]
fn test_is_hot_confirmed_pattern_fails_closed_on_out_of_bounds() {
    let scanner = CompiledScanner::compile(vec![]).expect("empty scanner compiles");
    assert!(!scanner.is_hot_confirmed_pattern(usize::MAX));
    assert!(!scanner.is_hot_confirmed_pattern(999_999));
}
#[test]
fn mixed_batch_topology_never_serializes_a_large_chunk_with_neighbors() {
    const THRESHOLD: usize = 8;
    const WORKERS: usize = 8;
    let mut sizes = vec![THRESHOLD; 999];
    sizes.insert(500, THRESHOLD + 1);

    let lanes = keyhog_scanner::testing::chunk_lane_topology_for_test(&sizes, THRESHOLD, WORKERS);
    let large_lanes: Vec<&Vec<usize>> = lanes
        .iter()
        .filter_map(|(is_large, indices)| is_large.then_some(indices))
        .collect();
    assert_eq!(large_lanes.len(), 1);
    assert_eq!(large_lanes[0].as_slice(), &[500]);

    let small_lanes: Vec<&Vec<usize>> = lanes
        .iter()
        .filter_map(|(is_large, indices)| (!is_large).then_some(indices))
        .collect();
    assert_eq!(small_lanes.len(), WORKERS);
    assert!(small_lanes.iter().all(|lane| lane.len() <= 125));
    assert!(small_lanes.iter().all(|lane| !lane.contains(&500)));

    let mut scheduled: Vec<usize> = lanes
        .iter()
        .flat_map(|(_, indices)| indices.iter().copied())
        .collect();
    scheduled.sort_unstable();
    assert_eq!(scheduled, (0..sizes.len()).collect::<Vec<_>>());
}

#[test]
fn small_lane_topology_uses_one_flat_index_buffer() {
    const CHUNKS: usize = 4096;
    const WORKERS: usize = 32;
    let sizes = vec![1; CHUNKS];
    let (small_lanes, stored_indices, index_buffers) =
        keyhog_scanner::testing::chunk_lane_storage_shape_for_test(&sizes, 64 * 1024, WORKERS);

    assert_eq!(small_lanes, WORKERS);
    assert_eq!(stored_indices, CHUNKS);
    assert_eq!(
        index_buffers, 1,
        "small-lane membership must use one flat index buffer, not one allocation per lane"
    );
}

/// WHY: compact lanes are trusted by both CPU dispatch and SIMD trigger
/// collection. This closes empty/worker-boundary/index coverage variants, but
/// does not measure scheduler timing.
#[test]
fn production_topology_covers_every_boundary_variant_exactly_once() {
    const THRESHOLD: usize = 8;
    const WORKERS: usize = 4;
    let cases = [
        ("empty", vec![], 0),
        ("zero-workers", vec![0, THRESHOLD, THRESHOLD + 1], 0),
        (
            "below-worker-count",
            vec![THRESHOLD, THRESHOLD + 1],
            WORKERS,
        ),
        ("equal-worker-count", vec![THRESHOLD; WORKERS], WORKERS),
        ("all-small", vec![THRESHOLD; WORKERS + 3], WORKERS),
        ("all-large", vec![THRESHOLD + 1; WORKERS + 3], WORKERS),
        (
            "mixed-boundary",
            vec![0, THRESHOLD, THRESHOLD + 1, 1, THRESHOLD + 2],
            WORKERS,
        ),
        (
            "large-worker-count",
            vec![0, THRESHOLD, THRESHOLD + 1],
            usize::MAX,
        ),
    ];

    for (name, sizes, workers) in cases {
        let lanes =
            keyhog_scanner::testing::chunk_lane_topology_for_test(&sizes, THRESHOLD, workers);
        let mut scheduled = Vec::new();
        for (is_large, indices) in &lanes {
            assert!(!indices.is_empty(), "{name}: empty work lane");
            if *is_large {
                assert_eq!(
                    indices.len(),
                    1,
                    "{name}: every large chunk must remain independently scheduled"
                );
                assert!(
                    sizes[indices[0]] > THRESHOLD,
                    "{name}: large lane contains a small chunk"
                );
            } else {
                assert!(
                    indices.iter().all(|&index| sizes[index] <= THRESHOLD),
                    "{name}: small lane contains a large chunk"
                );
            }
            scheduled.extend(indices.iter().copied());
            assert!(
                indices.iter().all(|&index| index < sizes.len()),
                "{name}: lane index escaped the chunk batch"
            );
        }
        scheduled.sort_unstable();
        assert_eq!(
            scheduled,
            (0..sizes.len()).collect::<Vec<_>>(),
            "{name}: topology must schedule every chunk exactly once"
        );
    }
}

#[test]
fn pr27_review_chunk_lane_tuning_validates_bounds_and_reaches_runtime_state() {
    use keyhog_scanner::{GpuInitPolicy, ScannerTuningConfig};

    let valid_cases = [
        (None, 64 * 1024),
        (
            Some(ScannerTuningConfig::CHUNK_LANE_THRESHOLD_MIN),
            ScannerTuningConfig::CHUNK_LANE_THRESHOLD_MIN,
        ),
        (
            Some(ScannerTuningConfig::CHUNK_LANE_THRESHOLD_MAX),
            ScannerTuningConfig::CHUNK_LANE_THRESHOLD_MAX,
        ),
    ];
    for (configured, expected) in valid_cases {
        let tuning = ScannerTuningConfig {
            chunk_lane_threshold: configured,
            ..Default::default()
        };
        tuning.validate().expect("valid threshold");
        assert_eq!(tuning.effective().chunk_lane_threshold, expected);
        let scanner = CompiledScanner::compile_with_gpu_policy_and_tuning(
            vec![],
            GpuInitPolicy::ForceDisabled,
            &tuning,
        )
        .expect("valid tuning compiles");
        assert_eq!(
            keyhog_scanner::testing::scanner_chunk_lane_threshold_for_test(&scanner),
            expected
        );
    }

    let compatibility_tuning = ScannerTuningConfig {
        chunk_lane_threshold: Some(8 * 1024),
        ..Default::default()
    };
    #[allow(deprecated)]
    let compatibility_scanner = CompiledScanner::compile(vec![])
        .expect("default scanner compiles")
        .with_tuning_config(compatibility_tuning);
    assert_eq!(
        keyhog_scanner::testing::scanner_chunk_lane_threshold_for_test(&compatibility_scanner),
        8 * 1024,
        "the original infallible builder signature must remain source-compatible"
    );

    for invalid in [
        ScannerTuningConfig::CHUNK_LANE_THRESHOLD_MIN - 1,
        ScannerTuningConfig::CHUNK_LANE_THRESHOLD_MAX + 1,
        usize::MAX,
    ] {
        let tuning = ScannerTuningConfig {
            chunk_lane_threshold: Some(invalid),
            ..Default::default()
        };
        assert_eq!(
            tuning.effective().chunk_lane_threshold,
            invalid,
            "effective config must not silently substitute the default"
        );
        assert!(tuning.validate().is_err());
        assert!(
            CompiledScanner::compile_with_gpu_policy_and_tuning(
                vec![],
                GpuInitPolicy::ForceDisabled,
                &tuning,
            )
            .is_err(),
            "invalid threshold {invalid} must fail scanner construction"
        );
        assert!(
            CompiledScanner::compile(vec![])
                .expect("default scanner compiles")
                .try_with_tuning_config(tuning)
                .is_err(),
            "invalid threshold {invalid} must fail post-compile tuning"
        );
    }
}

#[test]
fn worker_local_scratch_drops_pathological_capacity_before_reuse() {
    let (entropy_capacity, entropy_ceiling, confirmed_capacity, confirmed_ceiling) =
        keyhog_scanner::testing::scratch_retention_after_growth_for_test(10_000);
    assert!(entropy_capacity <= entropy_ceiling);
    assert!(confirmed_capacity <= confirmed_ceiling);

    let (
        small_entropy_capacity,
        small_entropy_ceiling,
        small_confirmed_capacity,
        small_confirmed_ceiling,
    ) = keyhog_scanner::testing::scratch_retention_after_growth_for_test(8);
    assert_eq!(small_entropy_ceiling, entropy_ceiling);
    assert_eq!(small_confirmed_ceiling, confirmed_ceiling);
    assert!(small_entropy_capacity <= entropy_ceiling);
    assert!(small_confirmed_capacity <= confirmed_ceiling);
}
