use crate::engine::*;

#[test]
fn canonical_cap_is_one_million() {
    assert_eq!(keyhog_scanner::engine::MAX_INNER_LOOP_ITERS, 1_000_000);
}

#[test]
fn cap_is_whole_multiple_of_deadline_cadence() {
    assert_eq!(keyhog_scanner::deadline::HOT_LOOP_DEADLINE_CADENCE, 64);
    assert_eq!(
        keyhog_scanner::engine::MAX_INNER_LOOP_ITERS
            % keyhog_scanner::deadline::HOT_LOOP_DEADLINE_CADENCE,
        0
    );
    assert_eq!(
        keyhog_scanner::engine::MAX_INNER_LOOP_ITERS
            / keyhog_scanner::deadline::HOT_LOOP_DEADLINE_CADENCE,
        15_625
    );
}

#[test]
fn bigram_bloom_min_chunk_bytes_is_sixty_four() {
    assert_eq!(keyhog_scanner::engine::BIGRAM_BLOOM_MIN_CHUNK_BYTES, 64);
}

#[test]
fn boundary_seam_cap_matches_window_overlap() {
    assert_eq!(
        keyhog_scanner::engine::MAX_BOUNDARY_SEAM_BYTES,
        keyhog_scanner::types::WINDOW_OVERLAP_BYTES
    );
    assert_eq!(keyhog_scanner::engine::MAX_BOUNDARY_SEAM_BYTES, 128 * 1024);
}

#[test]
fn finish_partition_clears_every_cross_call_cache() {
    let scanner =
        CompiledScanner::compile_for_backend(vec![], crate::hw_probe::ScanBackend::CpuFallback)
            .unwrap();

    scanner
        .fragment_cache
        .record_and_reassemble(crate::fragment_cache::SecretFragment {
            prefix: "AKIA".to_string(),
            var_name: "AWS_ACCESS_KEY_ID".to_string(),
            value: zeroize::Zeroizing::new("1234567890123456".to_string()),
            line: 42,
            path: Some("src/main.rs".into()),
        });
    let (len_before, _, _) = scanner.fragment_cache.storage_for_test();
    assert!(len_before > 0);

    with_candidate_scratch(|scratch| {
        scratch.reserve_exact(1_024);
        scratch.push((1, 2));
    });
    assert!(candidate_scratch_idle_count_for_test() > 0);

    scanner.finish_partition();

    let (len_after, _, _) = scanner.fragment_cache.storage_for_test();
    assert_eq!(len_after, 0);
    assert!(scanner.reusable_phase1_evidence.lock().is_empty());
    assert_eq!(candidate_scratch_idle_count_for_test(), 0);
}
