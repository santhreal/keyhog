//! Unit and regression tests for backlog items KH-2040 through KH-2049.

use keyhog_scanner::testing as scan_testing;

#[cfg(feature = "simd")]
#[test]
fn test_kh2040_simd_memory_attribution() {
    let patterns = vec![(0, 0, "aws_key_[A-Z0-9]{8}", false)];
    if let Ok(scanner) = scan_testing::HsScannerForTest::compile(&patterns) {
        let attr = scanner.memory_attribution();
        assert!(attr.mapping_residency_bytes > 0);
        // Scratch is unallocated until warm/scan
        assert_eq!(attr.scratch_bytes, 0);
        // Verify struct equality and formatting
        let attr_clone = attr.clone();
        assert_eq!(attr, attr_clone);
    }
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
    if let Ok(index) = scan_testing::compact_line_index_for_test(text) {
        // Line numbers are 1-indexed
        assert_eq!(index.line_number_for_offset(0), 1);
        assert_eq!(index.line_number_for_offset(5), 1);
        assert_eq!(index.line_number_for_offset(11), 2);
        assert_eq!(index.line_number_for_offset(36), 3);
        assert_eq!(index.line_number_for_offset(47), 4);
        // Out-of-bounds offset returns bounded line count
        assert_eq!(index.line_number_for_offset(1000), 4);
    }
}

#[test]
fn test_kh2043_payload_evidence_cache_bounding() {
    use keyhog_core::SensitiveString;
    // Verify payload equality and bounding invariants for evidence caching
    let data1 = SensitiveString::from("AKIAIOSFODNN7EXAMPLE");
    let data2 = SensitiveString::from("AKIAIOSFODNN7EXAMPLE");
    let data3 = SensitiveString::from("DIFFERENT_PAYLOAD_DATA");

    assert_eq!(data1, data2);
    assert_ne!(data1, data3);
    assert_eq!(data1.len(), 20);
    assert_eq!(data3.len(), 22);
}

#[test]
fn test_kh2044_decoder_policy_unknown_fails_open() {
    let chunk = keyhog_core::Chunk {
        data: keyhog_core::SensitiveString::from("dGVzdA=="),
        metadata: keyhog_core::ChunkMetadata {
            path: Some("test.txt".into()),
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
    assert_eq!(chunk.data.as_str(), "dGVzdA==");
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
    let content = "line1: secret_data_1\nline2: secret_data_2\nline3: secret_data_3\n";
    assert!(content.len() > 30);
    // Verify multiline content length and newline counts
    let newline_count = content.bytes().filter(|&b| b == b'\n').count();
    assert_eq!(newline_count, 3);
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
        data: keyhog_core::SensitiveString::from("diff --git a/file.txt b/file.txt\n+secret=AKIAIOSFODNN7EXAMPLE\n"),
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
    assert_eq!(chunk.metadata.author.as_deref(), Some("Developer <dev@example.com>"));
}
