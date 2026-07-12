//! Chunk boundary straddle parity across all backends (module-pair test).
//!
//! The chunk-boundary reassembly path (`engine/boundary.rs`) synthesises a
//! seam buffer from adjacent chunks, using a scanner-derived bounded width or
//! the full adjacent pair for unbounded generators, then appends straddle
//! findings to the results. This path is ONLY exercised when the backend is
//! `SimdCpu` or `CpuFallback`
//! (`backend_dispatch.rs` shows GPU paths call `scan_chunk_boundaries`
//! after their own dispatch).
//!
//! This test **asserts that all backends produce identical findings when
//! chunks contain boundary-straddling secrets**, by:
//!
//!   1. Setting up two adjacent chunks where a credential straddles the seam.
//!   2. Scanning with each backend.
//!   3. Verifying the boundary finding appears in the same chunk index with
//!      the same offset, regardless of backend.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::BTreeSet;
use support::paths::detector_dir;

type FindingKey = (String, usize, usize);

fn collect_boundary_findings(results: &[Vec<keyhog_core::RawMatch>]) -> BTreeSet<FindingKey> {
    results
        .iter()
        .enumerate()
        .flat_map(|(chunk_idx, matches)| {
            matches.iter().map(move |m| {
                (
                    m.credential.as_ref().to_string(),
                    chunk_idx,
                    m.location.offset,
                )
            })
        })
        .collect()
}

fn make_chunk(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "boundary-test".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

#[test]
fn boundary_straddle_parity_aws_key_split_across_chunks() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // AWS access key: AKIA + 16 uppercase alphanumerics.
    let secret = concat!("AK", "IAQYLPMN5HFIQR7ZZZ");
    assert_eq!(secret.len(), 20);

    // Split at character 12, forcing the first 12 chars into chunk A
    // and the remaining 8 into chunk B.
    let split_at = 12;

    // Chunk A: padding + first part of secret at tail.
    // Use a 4096-byte chunk to ensure boundary distance.
    let pad_a_len = 4096 - split_at;
    let mut data_a = "x\n".repeat(pad_a_len / 2);
    if data_a.len() < pad_a_len {
        data_a.push('x');
    }
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    // Chunk B: rest of secret + boundary character.
    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");

    let chunk_a = make_chunk(&data_a, "boundary_test.txt", 0);
    let chunk_b = make_chunk(&data_b, "boundary_test.txt", len_a);

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
    ];

    scanner.clear_fragment_cache();
    let simd_results =
        scanner.scan_chunks_with_backend(&[chunk_a.clone(), chunk_b.clone()], ScanBackend::SimdCpu);
    let simd_keys = collect_boundary_findings(&simd_results);

    let mut failures = Vec::new();
    for backend in &backends[1..] {
        scanner.clear_fragment_cache();
        let results =
            scanner.scan_chunks_with_backend(&[chunk_a.clone(), chunk_b.clone()], *backend);
        let keys = collect_boundary_findings(&results);

        if keys != simd_keys {
            let only_simd: Vec<_> = simd_keys.difference(&keys).take(3).collect();
            let only_backend: Vec<_> = keys.difference(&simd_keys).take(3).collect();
            failures.push(format!(
                "[boundary/{backend:?}] parity broken: simd={} got={} \
                 only-in-simd={only_simd:?} only-in-backend={only_backend:?}",
                simd_keys.len(),
                keys.len()
            ));
        }
    }

    eprintln!(
        "boundary_straddle_parity: backends={} failures={}",
        backends.len(),
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "boundary straddle parity failures:\n  - {}",
        failures.join("\n  - ")
    );
}

#[test]
fn boundary_straddle_parity_github_pat_split_across_chunks() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // GitHub Personal Access Token: ghp_ + 36 base62 chars. The github detector
    // verifies the trailing CRC32 checksum, so a fabricated token with a random
    // tail is correctly rejected (memory: checksum-invalidates-fabricated-token-
    // fixtures). Use the valid-checksum token from the sibling coalesced-parity
    // test so the SIMD precondition (and the boundary reassembly it gates) holds.
    let secret = "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";
    let split_at = 20;

    let pad_a_len = 4096 - split_at;
    let mut data_a = "x\n".repeat(pad_a_len / 2);
    if data_a.len() < pad_a_len {
        data_a.push('x');
    }
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();

    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");

    let chunk_a = make_chunk(&data_a, "github_boundary.py", 0);
    let chunk_b = make_chunk(&data_b, "github_boundary.py", len_a);

    scanner.clear_fragment_cache();
    let simd_results =
        scanner.scan_chunks_with_backend(&[chunk_a.clone(), chunk_b.clone()], ScanBackend::SimdCpu);
    let simd_findings: Vec<_> = simd_results
        .iter()
        .flat_map(|chunk| chunk.iter())
        .filter(|m| m.credential.as_ref().contains(secret))
        .collect();

    assert!(
        !simd_findings.is_empty(),
        "boundary straddle test setup failed: SIMD must find the split secret"
    );

    scanner.clear_fragment_cache();
    let fallback_results =
        scanner.scan_chunks_with_backend(&[chunk_a, chunk_b], ScanBackend::CpuFallback);
    let fallback_findings: Vec<_> = fallback_results
        .iter()
        .flat_map(|chunk| chunk.iter())
        .filter(|m| m.credential.as_ref().contains(secret))
        .collect();

    assert!(
        !fallback_findings.is_empty(),
        "CpuFallback boundary straddle: must find the same split secret as SIMD"
    );

    assert_eq!(
        simd_findings.len(),
        fallback_findings.len(),
        "boundary straddle findings count mismatch: SIMD={} CpuFallback={}",
        simd_findings.len(),
        fallback_findings.len()
    );
}
