//! Backend parity on empty chunks and edge cases.
//!
//! Tests that all backends handle empty chunks, whitespace-only chunks,
//! and boundary conditions consistently. These edge cases stress:
//!
//!   1. Empty chunk handling (zero findings expected).
//!   2. Whitespace-only chunks with no content.
//!   3. Single-byte chunks (tests UTF-8 boundary handling).
//!   4. Mixed empty and non-empty chunks (tests coalesced dispatch).

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::ScanBackend;
use support::compile_full_detector_scanner;

fn backends() -> Vec<ScanBackend> {
    let mut backends = vec![ScanBackend::SimdCpu, ScanBackend::CpuFallback];
    #[cfg(feature = "gpu")]
    backends.extend([ScanBackend::GpuWgpu]);
    backends
}

fn make_chunk(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "edge-test".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

#[test]
fn empty_chunk_all_backends_produce_zero_findings() {
    let scanner = compile_full_detector_scanner();

    let empty_chunk = make_chunk("", "empty.txt", 0);

    for backend in backends() {
        scanner.clear_fragment_cache();
        let degrade_before = scanner.runtime_status().gpu_degrade_count;
        let results = scanner.scan_chunks_with_backend(&[empty_chunk.clone()], backend);
        let degrade_after = scanner.runtime_status().gpu_degrade_count;

        assert_eq!(results, vec![Vec::new()], "empty chunk on {backend:?}");
        assert_eq!(degrade_after, degrade_before, "{backend:?} degraded");
    }
}

#[test]
fn whitespace_only_chunk_all_backends_produce_zero_findings() {
    let scanner = compile_full_detector_scanner();

    let whitespace_chunk = make_chunk("   \n\t\n   \r\n   ", "whitespace.txt", 0);

    for backend in backends() {
        scanner.clear_fragment_cache();
        let degrade_before = scanner.runtime_status().gpu_degrade_count;
        let results = scanner.scan_chunks_with_backend(&[whitespace_chunk.clone()], backend);
        let degrade_after = scanner.runtime_status().gpu_degrade_count;
        assert_eq!(results, vec![Vec::new()], "whitespace chunk on {backend:?}");
        assert_eq!(degrade_after, degrade_before, "{backend:?} degraded");
    }
}

#[test]
fn single_byte_chunk_is_empty_on_all_backends_without_degrade() {
    let scanner = compile_full_detector_scanner();

    let single_byte_chunk = make_chunk("x", "one.txt", 0);

    for backend in backends() {
        scanner.clear_fragment_cache();
        let degrade_before = scanner.runtime_status().gpu_degrade_count;
        let results = scanner.scan_chunks_with_backend(&[single_byte_chunk.clone()], backend);
        let degrade_after = scanner.runtime_status().gpu_degrade_count;
        assert_eq!(results, vec![Vec::new()], "single byte on {backend:?}");
        assert_eq!(degrade_after, degrade_before, "{backend:?} degraded");
    }
}

#[test]
fn mixed_empty_and_nonempty_chunks_coalesced_dispatch_parity() {
    let scanner = compile_full_detector_scanner();

    // Mix of empty and non-empty chunks in a single batch.
    let chunks = vec![
        make_chunk("", "empty1.txt", 0),
        make_chunk("const KEY = \"AKIAQYLPMN5HFIQR7AAA\";", "has_secret.rs", 0),
        make_chunk("", "empty2.txt", 0),
        make_chunk("// just a comment\n", "comment.txt", 0),
        make_chunk(
            "const PAT = \"ghp_aBcD1234EFgh5678ijklMNop9012qrSTuvWX\";",
            "another_secret.py",
            0,
        ),
    ];

    scanner.clear_fragment_cache();
    let simd_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    assert!(
        simd_results.iter().flatten().next().is_some(),
        "mixed reference must contain a real finding"
    );

    for backend in backends().into_iter().skip(1) {
        scanner.clear_fragment_cache();
        let degrade_before = scanner.runtime_status().gpu_degrade_count;
        let results = scanner.scan_chunks_with_backend(&chunks, backend);
        let degrade_after = scanner.runtime_status().gpu_degrade_count;
        assert_eq!(
            results, simd_results,
            "{backend:?} must preserve complete findings and per-chunk grouping"
        );
        assert_eq!(degrade_after, degrade_before, "{backend:?} degraded");
    }
}
