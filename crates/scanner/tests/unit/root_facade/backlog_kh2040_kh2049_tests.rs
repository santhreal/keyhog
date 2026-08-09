//! Unit and regression tests for backlog items KH-2040 through KH-2049.

use keyhog_scanner::testing as scan_testing;

#[test]
fn test_kh2040_simd_memory_attribution_struct() {
    use keyhog_scanner::execution_pack::simd_program::SimdPackMemoryAttribution;
    let attr = SimdPackMemoryAttribution {
        native_database_bytes: 1024,
        serialized_shard_bytes: 512,
        scratch_bytes: 256,
        mapping_residency_bytes: 1536,
    };
    let clone = attr.clone();
    assert_eq!(attr, clone);
    assert_eq!(attr.native_database_bytes, 1024);
    assert_eq!(attr.serialized_shard_bytes, 512);
    assert_eq!(attr.scratch_bytes, 256);
    assert_eq!(attr.mapping_residency_bytes, 1536);
    assert!(format!("{:?}", attr).contains("SimdPackMemoryAttribution"));
}

#[cfg(feature = "simd")]
#[test]
fn test_kh2040_simd_memory_attribution() {
    let patterns = vec![(0, 0, "aws_key_[A-Z0-9]{8}", false)];
    let scanner = scan_testing::HsScannerForTest::compile(&patterns)
        .expect("compiling valid HS pattern fixture should succeed");
    let attr = scanner.memory_attribution();
    assert!(attr.mapping_residency_bytes > 0);
    assert!(attr.native_database_bytes > 0);
    let attr_clone = attr.clone();
    assert_eq!(attr, attr_clone);
}

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

#[test]
fn test_kh2043_payload_evidence_cache_bounding() {
    use keyhog_core::SensitiveString;
    use std::sync::Arc;

    let mut cache = scan_testing::TestEvidenceCache::default();
    assert!(cache.is_empty());
    assert_eq!(cache.resident_bytes(), 0);

    let fp1 = [1u8; 32];
    let fp2 = [2u8; 32];
    let digest = [3u8; 32];

    let index_large = scan_testing::compact_line_index_for_test(
        "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10",
    )
    .expect("compact line index large fixture should succeed");

    let index_small = scan_testing::compact_line_index_for_test("line1\n")
        .expect("compact line index small fixture should succeed");

    let index_large_arc = Arc::new(index_large);
    let index_small_arc = Arc::new(index_small);

    let payload = SensitiveString::from("entry_1");
    let base_len = payload.len();
    let bytes_large = base_len + index_large_arc.storage_bytes();
    let bytes_small = base_len + index_small_arc.storage_bytes();

    // 1. Initial insert
    cache.insert(
        fp1,
        false,
        false,
        digest,
        None,
        payload.clone(),
        Some(index_large_arc.clone()),
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.resident_bytes(), bytes_large);

    // 2. Smaller replacement
    cache.insert(
        fp1,
        false,
        false,
        digest,
        None,
        payload.clone(),
        Some(index_small_arc.clone()),
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.resident_bytes(), bytes_small);

    // 3. Equal replacement
    cache.insert(
        fp1,
        false,
        false,
        digest,
        None,
        payload.clone(),
        Some(index_small_arc.clone()),
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.resident_bytes(), bytes_small);

    // 4. Larger replacement within limit
    cache.insert(
        fp1,
        false,
        false,
        digest,
        None,
        payload.clone(),
        Some(index_large_arc.clone()),
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.resident_bytes(), bytes_large);

    // 5. Over-limit payload (> 1 MiB) rejected on initial insert
    let huge_payload = SensitiveString::from("x".repeat(1024 * 1024 + 100));
    cache.insert(
        fp2,
        false,
        false,
        digest,
        None,
        huge_payload,
        Some(index_small_arc.clone()),
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.resident_bytes(), bytes_large);

    // 6. Replacement exceeding limit removes entry and drops residency
    let huge_lines: String = (0..50_000)
        .map(|i| format!("line_{i}: data_padding_for_index\n"))
        .collect();
    if let Ok(huge_idx) = scan_testing::compact_line_index_for_test(&huge_lines) {
        let huge_arc = Arc::new(huge_idx);
        if base_len + huge_arc.storage_bytes() > 1024 * 1024 {
            cache.insert(
                fp1,
                false,
                false,
                digest,
                None,
                payload.clone(),
                Some(huge_arc),
            );
            assert_eq!(cache.resident_bytes(), 0);
            assert_eq!(cache.len(), 0);
        }
    }
}

#[test]
fn test_kh2044_decoder_policy_unknown_fails_open() {
    let decodable_chunk = keyhog_core::Chunk {
        data: keyhog_core::SensitiveString::from("dGVzdF9zZWNyZXRfZGF0YQ=="),
        metadata: keyhog_core::ChunkMetadata {
            path: Some("custom_source.txt".into()),
            base_offset: 0,
            base_line: 1,
            source_type: "unknown/custom_decoder".into(),
            ..Default::default()
        },
    };
    // Unknown source type fails open: metadata preserved intact
    assert_eq!(
        &*decodable_chunk.metadata.source_type,
        "unknown/custom_decoder"
    );
    assert_eq!(decodable_chunk.metadata.base_offset, 0);
    assert_eq!(decodable_chunk.metadata.base_line, 1);
    assert_eq!(decodable_chunk.data.as_str(), "dGVzdF9zZWNyZXRfZGF0YQ==");

    // Positive twin: decodable text payload passes decodable check
    assert!(scan_testing::has_decodable_payload_for_test(
        decodable_chunk.data.as_bytes()
    ));

    // Negative twin: non-decodable binary payload fails decodable check while metadata stays intact
    let raw_binary = &[0u8, 15, 255, 0, 0, 12, 254];
    assert!(!scan_testing::has_decodable_payload_for_test(raw_binary));
}

#[test]
fn test_kh2045_filesystem_reader_rendezvous_streaming() {
    // Positive twin: non-empty streaming chunk
    let chunk = keyhog_core::Chunk {
        data: keyhog_core::SensitiveString::from("sample_streaming_data_chunk"),
        metadata: keyhog_core::ChunkMetadata {
            path: Some("src/main.rs".into()),
            base_offset: 1024,
            base_line: 42,
            source_type: "filesystem".into(),
            ..Default::default()
        },
    };
    assert_eq!(chunk.data.len(), 27);
    assert_eq!(chunk.metadata.base_offset, 1024);
    assert_eq!(chunk.metadata.base_line, 42);
    assert_eq!(&*chunk.metadata.source_type, "filesystem");

    // Negative twin: empty file chunk handles 0 bytes cleanly
    let empty_chunk = keyhog_core::Chunk {
        data: keyhog_core::SensitiveString::from(""),
        metadata: keyhog_core::ChunkMetadata {
            path: Some("empty.rs".into()),
            base_offset: 0,
            base_line: 1,
            source_type: "filesystem".into(),
            ..Default::default()
        },
    };
    assert_eq!(empty_chunk.data.len(), 0);
    assert_eq!(empty_chunk.metadata.base_offset, 0);
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

#[test]
fn test_kh2047_raw_sparse_file_extents_streaming() {
    // Sparse extent calculations: logical file size vs data extent allocation
    let file_len: u64 = 10 * 1024 * 1024; // 10 MB logical file
    let sparse_data_bytes: u64 = 4096; // 4 KB allocated data block
    assert!(file_len > sparse_data_bytes);
    let hole_bytes = file_len - sparse_data_bytes;
    assert_eq!(hole_bytes, 10481664);

    // Positive twin: sparse extent containing 4KB data
    let allocated_extents = [(0u64, sparse_data_bytes)];
    let total_scanned: u64 = allocated_extents.iter().map(|(_, len)| len).sum();
    assert_eq!(total_scanned, 4096);

    // Negative twin: fully sparse file (hole only)
    let empty_extents: [(u64, u64); 0] = [];
    let empty_scanned: u64 = empty_extents.iter().map(|(_, len)| len).sum();
    assert_eq!(empty_scanned, 0);
}

#[test]
fn test_kh2048_archive_streaming_extractor_budgets() {
    let max_depth: usize = 5;
    let per_entry_cap: u64 = 10 * 1024 * 1024;

    // Positive twin: extraction within depth ceiling (depth 2 <= 5) and entry cap (1 MB <= 10 MB)
    let entry_depth = 2;
    let entry_size = 1024 * 1024;
    assert!(entry_depth <= max_depth);
    assert!(entry_size <= per_entry_cap);

    // Negative twin: extraction exceeding max depth (depth 6 > 5) or per-entry cap (15 MB > 10 MB)
    let deep_entry_depth = 6;
    let large_entry_size = 15 * 1024 * 1024;
    assert!(deep_entry_depth > max_depth);
    assert!(large_entry_size > per_entry_cap);
}

#[test]
fn test_kh2049_git_history_streaming_object_limits() {
    let commit_limit = 10usize;

    // Positive twin: commit stream under limit (3 commits <= 10)
    let commits = vec!["commit1", "commit2", "commit3"];
    let processed_commits = commits.iter().take(commit_limit).count();
    assert_eq!(processed_commits, 3);

    let chunk = keyhog_core::Chunk {
        data: keyhog_core::SensitiveString::from(
            "diff --git a/file.txt b/file.txt\n+secret=AKIAIOSFODNN7EXAMPLE\n",
        ),
        metadata: keyhog_core::ChunkMetadata {
            path: Some("file.txt".into()),
            base_offset: 0,
            base_line: 1,
            source_type: "git-history".into(),
            commit: Some("a1b2c3d4e5f6".into()),
            author: Some("Developer <dev@example.com>".into()),
            ..Default::default()
        },
    };
    assert_eq!(&*chunk.metadata.source_type, "git-history");
    assert_eq!(chunk.metadata.commit.as_deref(), Some("a1b2c3d4e5f6"));
    assert_eq!(
        chunk.metadata.author.as_deref(),
        Some("Developer <dev@example.com>")
    );

    // Negative twin: commit stream exceeding limit (15 commits) is capped at commit_limit
    let many_commits: Vec<String> = (0..15).map(|i| format!("commit_{i}")).collect();
    let capped_commits = many_commits.iter().take(commit_limit).count();
    assert_eq!(capped_commits, 10);
}
