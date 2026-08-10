//! Unit and regression tests for backlog items KH-2040 through KH-2049.

use keyhog_scanner::testing as scan_testing;

#[cfg(feature = "simd")]
#[test]
fn test_kh2040_shard_page_release_owned_and_mapped() {
    use keyhog_scanner::execution_pack::simd_program::SerializedHyperscanShard;

    let owned_shard = SerializedHyperscanShard::from(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(owned_shard.len(), 8);
    // Page release on owned shard storage must return Ok(()) without issuing madvise
    assert!(owned_shard.release_resident_pages().is_ok());
}

#[test]
fn test_kh2041_lazy_companion_activation_checks() {
    let lazy_comp = scan_testing::companion_lazy_regex_for_test("sk_live_[a-zA-Z0-9]{24}");
    assert!(!lazy_comp.is_compiled());

    let rx = lazy_comp.get();
    assert!(lazy_comp.is_compiled());

    // Positive twin: matching credential string
    assert!(rx.is_match("sk_live_123456789012345678901234"));
    // Negative twin: non-matching string
    assert!(!rx.is_match("sk_test_invalid_token"));
}

#[test]
fn test_kh2042_coordinate_line_index_reuse_passthrough() {
    let text = "first line\nsecond line with secret\r\nthird line\nfourth line";
    let index = scan_testing::compact_line_index_for_test(text)
        .expect("building line index fixture should succeed");
    assert_eq!(index.line_number_for_offset(0), 1);
    assert_eq!(index.line_number_for_offset(5), 1);
    assert_eq!(index.line_number_for_offset(11), 2);
    assert_eq!(index.line_number_for_offset(36), 3);
    assert_eq!(index.line_number_for_offset(47), 4);
    assert_eq!(index.line_number_for_offset(1000), 4);
    assert!(index.storage_bytes() > 0);

    let single_line = "no_newline_text";
    let index = scan_testing::compact_line_index_for_test(single_line)
        .expect("building single line index fixture should succeed");
    assert_eq!(index.line_number_for_offset(0), 1);
    assert_eq!(index.line_number_for_offset(5), 1);
    assert_eq!(index.line_number_for_offset(100), 1);
}

fn line_index_at_least(bytes: usize) -> std::sync::Arc<scan_testing::CompactLineIndexForTest> {
    let text = "\n".repeat(bytes / std::mem::size_of::<u32>() + 1);
    let index = scan_testing::compact_line_index_for_test(&text)
        .expect("bounded newline fixture must produce a compact line index");
    assert!(
        index.storage_bytes() >= bytes,
        "line-index fixture did not reach the requested allocation"
    );
    std::sync::Arc::new(index)
}

fn assert_cache_is_bounded(cache: &scan_testing::TestEvidenceCache) {
    assert_eq!(
        cache.resident_bytes(),
        cache.aggregate_resident_bytes(),
        "tracked residency diverged from the sum of cached allocations"
    );
    assert!(
        cache.resident_bytes() <= scan_testing::TestEvidenceCache::max_resident_bytes(),
        "cache exceeded its production resident-byte ceiling"
    );
    assert!(
        cache.len() <= scan_testing::TestEvidenceCache::max_entries(),
        "cache exceeded its production entry-count ceiling"
    );
}

#[test]
fn test_kh2043_payload_evidence_cache_replacement_and_bounding() {
    use keyhog_core::SensitiveString;
    use std::time::{Duration, Instant};

    let limit = scan_testing::TestEvidenceCache::max_resident_bytes();
    let digest = [3u8; 32];
    let key = SensitiveString::from("replacement-key");
    let key_bytes = key.len();
    let small = line_index_at_least(64);
    let medium = line_index_at_least(limit / 3);
    let oversized = line_index_at_least(limit + 1);

    let mut allocated_evidence = scan_testing::TestEvidenceCache::default();
    allocated_evidence.insert_with_evidence_allocations(
        [8; 32],
        false,
        false,
        digest,
        None,
        key.clone(),
        11,
        13,
        17,
        None,
    );
    assert_eq!(
        allocated_evidence.resident_bytes(),
        key_bytes
            + 11 * std::mem::size_of::<u32>()
            + 13 * std::mem::size_of::<u32>()
            + 17 * std::mem::size_of::<u64>(),
        "keyword, generic-position, and CPU-trigger allocations must all count toward residency"
    );
    assert_cache_is_bounded(&allocated_evidence);

    let mut cache = scan_testing::TestEvidenceCache::default();
    cache.insert(
        [1; 32],
        false,
        false,
        digest,
        None,
        key.clone(),
        Some(medium.clone()),
    );
    assert_eq!(cache.resident_bytes(), key_bytes + medium.storage_bytes());
    assert_cache_is_bounded(&cache);

    cache.insert(
        [1; 32],
        false,
        false,
        digest,
        None,
        key.clone(),
        Some(small.clone()),
    );
    assert_eq!(cache.resident_bytes(), key_bytes + small.storage_bytes());
    assert_cache_is_bounded(&cache);

    cache.insert(
        [1; 32],
        false,
        false,
        digest,
        None,
        key.clone(),
        Some(small.clone()),
    );
    assert_eq!(cache.resident_bytes(), key_bytes + small.storage_bytes());
    assert_cache_is_bounded(&cache);

    cache.insert(
        [1; 32],
        false,
        false,
        digest,
        None,
        key.clone(),
        Some(medium.clone()),
    );
    assert_eq!(cache.resident_bytes(), key_bytes + medium.storage_bytes());
    assert_cache_is_bounded(&cache);

    let mut eviction_cache = scan_testing::TestEvidenceCache::default();
    let filler = SensitiveString::from("f".repeat(limit * 3 / 4));
    eviction_cache.insert([2; 32], false, false, digest, None, filler, None);
    eviction_cache.insert(
        [1; 32],
        false,
        false,
        digest,
        None,
        key.clone(),
        Some(small.clone()),
    );
    assert!(eviction_cache.contains_fingerprint([2; 32]));
    assert_cache_is_bounded(&eviction_cache);
    eviction_cache.insert(
        [1; 32],
        false,
        false,
        digest,
        None,
        key.clone(),
        Some(medium.clone()),
    );
    assert!(
        eviction_cache.contains_fingerprint([1; 32]),
        "larger replacement was not retained"
    );
    assert!(
        !eviction_cache.contains_fingerprint([2; 32]),
        "larger replacement did not evict the other least-recent entry"
    );
    assert_cache_is_bounded(&eviction_cache);

    let neighbor = SensitiveString::from("neighbor");
    eviction_cache.insert(
        [5; 32],
        false,
        false,
        digest,
        None,
        neighbor,
        Some(small.clone()),
    );
    assert!(eviction_cache.contains_fingerprint([5; 32]));
    assert_cache_is_bounded(&eviction_cache);

    eviction_cache.insert(
        [1; 32],
        false,
        false,
        digest,
        None,
        key.clone(),
        Some(oversized.clone()),
    );
    assert!(
        !eviction_cache.contains_fingerprint([1; 32]),
        "an individually over-limit replacement remained cached"
    );
    assert!(
        eviction_cache.contains_fingerprint([5; 32]),
        "an over-limit replacement evicted an unrelated entry"
    );
    assert_cache_is_bounded(&eviction_cache);

    let mut boundary_cache = scan_testing::TestEvidenceCache::default();
    boundary_cache.insert(
        [3; 32],
        false,
        false,
        digest,
        None,
        SensitiveString::from("b".repeat(limit)),
        None,
    );
    assert_eq!(boundary_cache.resident_bytes(), limit);
    assert_cache_is_bounded(&boundary_cache);
    boundary_cache.insert(
        [4; 32],
        false,
        false,
        digest,
        None,
        SensitiveString::from("b".repeat(limit + 1)),
        None,
    );
    assert!(boundary_cache.contains_fingerprint([3; 32]));
    assert!(!boundary_cache.contains_fingerprint([4; 32]));
    assert_cache_is_bounded(&boundary_cache);

    let mut entry_bounded = scan_testing::TestEvidenceCache::default();
    for value in 0..=scan_testing::TestEvidenceCache::max_entries() {
        entry_bounded.insert(
            [u8::try_from(value).expect("test entry count fits u8"); 32],
            false,
            false,
            digest,
            None,
            SensitiveString::from(format!("entry-{value}")),
            None,
        );
        assert_cache_is_bounded(&entry_bounded);
    }
    assert!(!entry_bounded.contains_fingerprint([0; 32]));
    assert!(entry_bounded.contains_fingerprint(
        [u8::try_from(scan_testing::TestEvidenceCache::max_entries())
            .expect("production entry limit fits u8"); 32]
    ));
    entry_bounded.insert(
        [8; 32],
        false,
        false,
        digest,
        None,
        SensitiveString::from("entry-8"),
        Some(small.clone()),
    );
    assert_eq!(
        entry_bounded.len(),
        scan_testing::TestEvidenceCache::max_entries(),
        "replacement at the entry limit changed the entry count"
    );
    assert!(entry_bounded.contains_fingerprint([8; 32]));
    assert_cache_is_bounded(&entry_bounded);

    let mut repeated = scan_testing::TestEvidenceCache::default();
    let started = Instant::now();
    for replacement in 0..256 {
        repeated.insert(
            [9; 32],
            false,
            false,
            digest,
            None,
            key.clone(),
            Some(if replacement % 2 == 0 {
                small.clone()
            } else {
                medium.clone()
            }),
        );
        assert_eq!(repeated.len(), 1);
        assert_cache_is_bounded(&repeated);
    }
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "bounded replacement sequence did not terminate promptly"
    );
}

#[cfg(feature = "decode")]
#[test]
fn test_kh2044_decoder_policy_unknown_fails_open() {
    let chunk = keyhog_core::Chunk {
        data: keyhog_core::SensitiveString::from(
            "ordinary source\nconst ordinary_value = 1234567890;\n",
        ),
        metadata: keyhog_core::ChunkMetadata {
            path: Some("custom_source.txt".into()),
            source_type: "unknown/custom_decoder".into(),
            ..Default::default()
        },
    };
    let sketch = scan_testing::decode_admission_sketch_with_custom_unknown(&chunk);
    assert_eq!(
        sketch.kind_mask(),
        0,
        "ordinary input unexpectedly admitted a built-in decoder"
    );
    assert!(
        sketch.has_unknown(),
        "an unclassified decoder must remain fail-open"
    );
}

#[test]
fn test_kh2046_windowed_reading_gapless_byte_coverage() {
    let text =
        "line1: secret_data_1\nline2: secret_data_2\nline3: secret_data_3\nline4: secret_data_4\n";

    // Newline counting
    let newline_count = scan_testing::bytecount_newlines_for_test(text.as_bytes());
    assert_eq!(newline_count, 4);

    // Positive twin: gapless window coverage for line 2
    let window_line_2 = scan_testing::local_context_window_for_test(text, 2, 1);
    assert!(window_line_2.contains("line1"));
    assert!(window_line_2.contains("line2"));
    assert!(window_line_2.contains("line3"));

    let window_line_1 = scan_testing::local_context_window_for_test(text, 1, 2);
    assert!(window_line_1.starts_with("line1"));

    // Negative twin: out of bounds window line returns empty string safely
    let window_past_end = scan_testing::local_context_window_for_test(text, 100, 1);
    assert_eq!(window_past_end, "");
}
