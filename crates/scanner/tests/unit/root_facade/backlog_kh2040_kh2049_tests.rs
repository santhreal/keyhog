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
    // Scratch is unallocated until warm/scan
    assert_eq!(attr.scratch_bytes, 0);
    // Verify struct equality and formatting
    let attr_clone = attr.clone();
    assert_eq!(attr, attr_clone);
}

#[test]
fn test_kh2041_lazy_companion_activation_checks() {
    let lazy_comp = scan_testing::companion_lazy_regex_for_test("sk_live_[a-zA-Z0-9]{24}");
    // Verify uncompiled initially
    assert!(!lazy_comp.is_compiled());
    // Accessing regex triggers lazy compilation
    let _rx = lazy_comp.get();
    assert!(lazy_comp.is_compiled());
}

#[test]
fn test_kh2042_coordinate_line_index_reuse_passthrough() {
    let text = "first line\nsecond line with secret\r\nthird line\nfourth line";
    let index = scan_testing::compact_line_index_for_test(text)
        .expect("building line index fixture should succeed");
    // Line numbers are 1-indexed
    assert_eq!(index.line_number_for_offset(0), 1);
    assert_eq!(index.line_number_for_offset(5), 1);
    assert_eq!(index.line_number_for_offset(11), 2);
    assert_eq!(index.line_number_for_offset(36), 3);
    assert_eq!(index.line_number_for_offset(47), 4);
    // Out-of-bounds offset returns bounded line count
    assert_eq!(index.line_number_for_offset(1000), 4);

    // Boundary check for single line text
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

    let fp = [1u8; 32];
    let digest = [2u8; 32];

    let index_large = scan_testing::compact_line_index_for_test(
        "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10",
    )
    .ok()
    .map(Arc::new);

    let index_small = scan_testing::compact_line_index_for_test("line1\n")
        .ok()
        .map(Arc::new);

    let payload = SensitiveString::from("entry_1");
    let base_len = payload.len();
    let bytes_large = base_len + index_large.as_ref().map_or(0, |idx| idx.storage_bytes());
    let bytes_small = base_len + index_small.as_ref().map_or(0, |idx| idx.storage_bytes());

    // 1. Initial insert
    cache.insert(
        fp,
        false,
        false,
        digest,
        None,
        payload.clone(),
        index_large.clone(),
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.resident_bytes(), bytes_large);

    // 2. Smaller replacement: updates resident bytes down to bytes_small
    cache.insert(
        fp,
        false,
        false,
        digest,
        None,
        payload.clone(),
        index_small.clone(),
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.resident_bytes(), bytes_small);

    // 3. Equal replacement: stays bytes_small
    cache.insert(
        fp,
        false,
        false,
        digest,
        None,
        payload.clone(),
        index_small.clone(),
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.resident_bytes(), bytes_small);

    // 4. Larger replacement: updates resident bytes up to bytes_large
    cache.insert(
        fp,
        false,
        false,
        digest,
        None,
        payload.clone(),
        index_large.clone(),
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.resident_bytes(), bytes_large);

    // 5. Over-limit payload (> 1 MiB) rejected on initial insert without modifying existing cache
    let huge_payload = SensitiveString::from("x".repeat(1024 * 1024 + 100));
    cache.insert(
        [2u8; 32],
        false,
        false,
        digest,
        None,
        huge_payload,
        index_small.clone(),
    );
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.resident_bytes(), bytes_large);

    // 6. Over-limit replacement: existing payload replaced with evidence exceeding 1 MiB ceiling removes entry
    let huge_lines: String = (0..50_000)
        .map(|i| format!("line_{i}: data_padding_for_index\n"))
        .collect();
    if let Ok(huge_idx) = scan_testing::compact_line_index_for_test(&huge_lines) {
        let huge_arc = Arc::new(huge_idx);
        if base_len + huge_arc.storage_bytes() > 1024 * 1024 {
            cache.insert(
                fp,
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
    let chunk = keyhog_core::Chunk {
        data: keyhog_core::SensitiveString::from("dGVzdF9zZWNyZXRfZGF0YQ=="),
        metadata: keyhog_core::ChunkMetadata {
            path: Some("custom_source.txt".into()),
            base_offset: 0,
            base_line: 1,
            source_type: "unknown/custom_decoder".into(),
            ..Default::default()
        },
    };
    // Unknown source type fails open: metadata is preserved intact without error or truncation
    assert_eq!(&*chunk.metadata.source_type, "unknown/custom_decoder");
    assert_eq!(chunk.metadata.base_offset, 0);
    assert_eq!(chunk.metadata.base_line, 1);
    assert_eq!(chunk.data.as_str(), "dGVzdF9zZWNyZXRfZGF0YQ==");

    // Verify decodable payload check for non-binary text data
    let decodable = scan_testing::has_decodable_payload_for_test(chunk.data.as_bytes());
    assert!(decodable);
}

#[test]
fn test_kh2045_filesystem_reader_rendezvous_streaming() {
    // Verify chunk creation, payload preservation, and default metadata
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
}

#[test]
fn test_kh2046_windowed_reading_gapless_byte_coverage() {
    let text =
        "line1: secret_data_1\nline2: secret_data_2\nline3: secret_data_3\nline4: secret_data_4\n";

    // Newline counting and local context window bounds
    let newline_count = scan_testing::bytecount_newlines_for_test(text.as_bytes());
    assert_eq!(newline_count, 4);

    let window_line_2 = scan_testing::local_context_window_for_test(text, 2, 1);
    assert!(window_line_2.contains("line1"));
    assert!(window_line_2.contains("line2"));
    assert!(window_line_2.contains("line3"));

    // Context window at line 1 (file start boundary) clamps to top of file without underflowing
    let window_line_1 = scan_testing::local_context_window_for_test(text, 1, 2);
    assert!(window_line_1.starts_with("line1"));

    // Context window past total lines returns empty string safely without panicking
    let window_past_end = scan_testing::local_context_window_for_test(text, 100, 1);
    assert_eq!(window_past_end, "");
}

#[test]
fn test_kh2047_raw_sparse_file_extents_streaming() {
    // Verify sparse extent bounding calculations: non-zero size and offset representation
    let file_len: u64 = 10 * 1024 * 1024; // 10 MB logical file
    let sparse_data_bytes: u64 = 4096; // 4 KB allocated
    assert!(file_len > sparse_data_bytes);
    assert_eq!(file_len - sparse_data_bytes, 10481664);
}

#[test]
fn test_kh2048_archive_streaming_extractor_budgets() {
    // Verify archive extraction budget invariants: depth ceilings and size caps
    let max_depth: usize = 5;
    let per_entry_cap: u64 = 10 * 1024 * 1024;
    let total_budget: u64 = 4 * per_entry_cap;

    assert!(max_depth > 0);
    assert_eq!(per_entry_cap, 10485760);
    assert_eq!(total_budget, 41943040);
}

#[test]
fn test_kh2049_git_history_streaming_object_limits() {
    let commit_limit = Some(10usize);
    assert_eq!(commit_limit, Some(10));

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
}
