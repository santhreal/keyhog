use super::{HsCompileOpts, HsScanner, MAX_HS_PATTERN_LEN};

/// WHY: a shard-build rejection used to leave a hole in Hyperscan database IDs while retaining
/// the pre-drop mapping, so execution-pack compilation rejected the serialized SIMD program.
#[test]
fn build_drop_reassigns_database_ids_and_preserves_canonical_mapping() {
    let overlong = "X".repeat(MAX_HS_PATTERN_LEN + 1);
    let patterns = [
        (10usize, 0usize, "KH_ZERO_[A-Z0-9]{8}", false),
        (11usize, 1usize, overlong.as_str(), false),
        (12usize, 2usize, "KH_DROP_[A-Z0-9]{8}", false),
        (13usize, 3usize, "KH_LATE_[A-Z0-9]{8}", false),
    ];
    let options = HsCompileOpts {
        shard_target: Some(usize::MAX),
        ..Default::default()
    };

    // Database ID 1 is canonical ID 2 after prepare-time rejection compacted ID 1 out.
    let (scanner, unsupported) = HsScanner::compile_with_forced_build_drop(&patterns, options, 1)
        .expect("forced shard-build drop recompiles the supported set");

    assert_eq!(
        unsupported,
        vec![1, 2],
        "prepare and build drops must retain their original canonical IDs for scalar recovery"
    );
    assert_eq!(
        scanner.execution_pattern_map(),
        &[(0, 10, 0, false), (3, 13, 3, false)],
        "supported rows must retain canonical IDs while database IDs become dense"
    );

    let mut live_ids = Vec::new();
    scanner
        .scan_matches_result(b"KH_LATE_AB12CD34", |database_id, _, _| {
            live_ids.push(database_id)
        })
        .expect("compacted scanner executes");
    assert_eq!(
        live_ids,
        vec![1],
        "the later supported pattern must be reassigned to database ID 1"
    );
    assert_eq!(scanner.pattern_info(1), Some((13, 3, false)));

    let serialized = scanner
        .serialize_database_shards()
        .expect("compacted shards serialize");
    let restored = HsScanner::from_serialized_database_shards(
        &serialized,
        scanner.execution_pattern_map().to_vec(),
    )
    .expect("compacted shards deserialize without pattern compilation");
    let mut restored_ids = Vec::new();
    restored
        .scan_matches_result(b"KH_LATE_AB12CD34", |database_id, _, _| {
            restored_ids.push(database_id)
        })
        .expect("deserialized compacted scanner executes");
    assert_eq!(restored_ids, vec![1]);
    assert_eq!(restored.pattern_info(1), Some((13, 3, false)));
}

/// WHY: a combined Hyperscan database can exceed an internal limit even when every pattern is
/// supported alone; treating that as unsupported loses exact structural findings on recovery.
#[test]
fn build_drop_repartitions_before_declaring_patterns_unsupported() {
    let patterns = [
        (10usize, 0usize, "KH_LEFT_[A-Z0-9]{8}", false),
        (11usize, 1usize, "KH_RIGHT_[A-Z0-9]{8}", false),
    ];
    let options = HsCompileOpts {
        shard_target: Some(usize::MAX),
        ..Default::default()
    };
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .expect("build isolated two-worker compiler");
    let (scanner, unsupported) = pool
        .install(|| HsScanner::compile_with_forced_retryable_build_drop(&patterns, options, 0))
        .expect("retryable combined-database failure repartitions");

    assert!(
        unsupported.is_empty(),
        "repartitioning must preserve patterns that compile in narrower shards"
    );
    assert_eq!(scanner.shard_count(), 2);
    assert_eq!(
        scanner.execution_pattern_map(),
        &[(0, 10, 0, false), (1, 11, 1, false)]
    );
    let mut live_ids = Vec::new();
    scanner
        .scan_matches_result(
            b"KH_LEFT_AB12CD34 KH_RIGHT_Z9Y8X7W6",
            |database_id, _, _| live_ids.push(database_id),
        )
        .expect("repartitioned scanner executes");
    live_ids.sort_unstable();
    assert_eq!(live_ids, vec![0, 1]);
}
