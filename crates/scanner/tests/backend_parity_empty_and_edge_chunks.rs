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
use keyhog_scanner::{CompiledScanner, ScanBackend};
use support::paths::detector_dir;

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
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let empty_chunk = make_chunk("", "empty.txt", 0);

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    for backend in backends {
        let results = scanner.scan_chunks_with_backend(&[empty_chunk.clone()], backend);
        let total_findings: usize = results.iter().map(|chunk| chunk.len()).sum();

        // Empty input should produce zero findings on every backend.
        assert_eq!(
            total_findings, 0,
            "Empty chunk on {backend:?} produced {total_findings} findings (expected 0)"
        );
    }
}

#[test]
fn whitespace_only_chunk_all_backends_produce_zero_findings() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let whitespace_chunk = make_chunk("   \n\t\n   \r\n   ", "whitespace.txt", 0);

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    let mut failures = Vec::new();
    let simd_results =
        scanner.scan_chunks_with_backend(&[whitespace_chunk.clone()], ScanBackend::SimdCpu);
    let simd_count: usize = simd_results.iter().map(|chunk| chunk.len()).sum();

    for backend in &backends[1..] {
        let results = scanner.scan_chunks_with_backend(&[whitespace_chunk.clone()], *backend);
        let count: usize = results.iter().map(|chunk| chunk.len()).sum();

        // GPU/MegaScan can silently degrade; skip on empty.
        if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan)
            && count == 0
            && simd_count == 0
        {
            continue;
        }

        if count != simd_count {
            failures.push(format!(
                "[whitespace/{backend:?}] count mismatch: simd={simd_count} got={count}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "whitespace-only chunk parity failures:\n  - {}",
        failures.join("\n  - ")
    );
}

#[test]
fn single_byte_chunk_no_panic_all_backends() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let single_byte_chunk = make_chunk("x", "one.txt", 0);

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    for backend in backends {
        // Should not panic on single-byte input.
        let results = scanner.scan_chunks_with_backend(&[single_byte_chunk.clone()], backend);
        let _total_findings: usize = results.iter().map(|chunk| chunk.len()).sum();
        // No assertion on finding count; just verify no panic.
    }
}

#[test]
fn mixed_empty_and_nonempty_chunks_coalesced_dispatch_parity() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

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

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    let simd_results = scanner.scan_chunks_with_backend(&chunks, ScanBackend::SimdCpu);
    let simd_counts: Vec<usize> = simd_results.iter().map(|chunk| chunk.len()).collect();

    let mut failures = Vec::new();
    for backend in &backends[1..] {
        let results = scanner.scan_chunks_with_backend(&chunks, *backend);
        let counts: Vec<usize> = results.iter().map(|chunk| chunk.len()).collect();

        // GPU/MegaScan can silently degrade.
        if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan) {
            if counts == vec![0; chunks.len()] && simd_counts != vec![0; chunks.len()] {
                eprintln!("SKIP: {backend:?} (no adapter, silent SIMD degrade)");
                continue;
            }
        }

        if counts != simd_counts {
            failures.push(format!(
                "[mixed/{backend:?}] per-chunk count mismatch: \
                 simd={simd_counts:?} got={counts:?}"
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "mixed empty/non-empty chunk parity failures:\n  - {}",
        failures.join("\n  - ")
    );
}
