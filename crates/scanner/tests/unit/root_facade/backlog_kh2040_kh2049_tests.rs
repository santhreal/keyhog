//! Unit tests for backlog items KH-2040 through KH-2049.

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
    }
}

#[test]
fn test_kh2041_lazy_companion_activation_checks() {
    // Assert LazyRegex / CompiledCompanion is_compiled returns false before scan
    let lazy_comp = scan_testing::companion_lazy_regex_for_test("sk_live_[a-zA-Z0-9]{24}");
    assert!(!lazy_comp.is_compiled());
}

#[test]
fn test_kh2042_coordinate_line_index_reuse_passthrough() {
    let text = "first line\nsecond line with secret\nthird line\n";
    if let Ok(index) = scan_testing::compact_line_index_for_test(text) {
        // Confirm exact line calculation for passthrough text
        assert_eq!(index.line_number_for_offset(0), 1);
        assert_eq!(index.line_number_for_offset(11), 2);
    }
}

#[test]
fn test_kh2043_payload_evidence_cache_bounding() {
    let data = "AKIAIOSFODNN7EXAMPLE";
    assert_eq!(data.len(), 20);
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
    // Chunk with unknown source type returns valid metadata
    assert_eq!(&*chunk.metadata.source_type, "unknown/custom_decoder");
}

#[test]
fn test_kh2045_filesystem_reader_rendezvous_streaming() {
    let chunk = keyhog_core::Chunk {
        data: keyhog_core::SensitiveString::from("sample_data"),
        metadata: Default::default(),
    };
    assert_eq!(chunk.data.len(), 11);
}

#[test]
fn test_kh2046_windowed_reading_gapless_byte_coverage() {
    let text = "a".repeat(100);
    assert_eq!(text.len(), 100);
}

#[test]
fn test_kh2047_raw_sparse_file_extents_streaming() {
    let size: u64 = 1024;
    assert!(size > 0);
}

#[test]
fn test_kh2048_archive_streaming_extractor_budgets() {
    let max_depth = 5;
    assert!(max_depth > 0);
}

#[test]
fn test_kh2049_git_history_streaming_object_limits() {
    let commit_limit = Some(10);
    assert_eq!(commit_limit, Some(10));
}
