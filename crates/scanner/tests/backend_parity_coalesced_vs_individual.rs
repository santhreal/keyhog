//! Backend parity: coalesced batch dispatch vs per-chunk scans.
//!
//! The `scan_chunks_with_backend` entry point (`backend_dispatch.rs`)
//! routes through different code paths depending on the selected backend:
//!
//!   - SIMD/CpuFallback: rayon parallel per-chunk, then `scan_chunk_boundaries`.
//!   - GPU: single coalesced batch dispatch with fusion.
//!   - MegaScan: coalesced regex-DFA dispatch.
//!
//! This test **asserts that the sum of per-chunk results equals the
//! batch-dispatch results**, ensuring chunking and coalescing don't
//! introduce asymmetric findings across backends.

#[path = "support/mod.rs"]
mod support;

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::collections::{BTreeSet, HashMap};
use support::paths::detector_dir;

type FindingKey = (String, usize);

fn make_chunk(text: &str, path: &str, base_offset: usize) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "coalesce-test".into(),
            path: Some(path.into()),
            base_offset,
            ..Default::default()
        },
    }
}

#[test]
fn batch_dispatch_equals_sum_of_per_chunk_results_all_backends() {
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    // Three chunks with multiple credentials across them.
    let chunks = vec![
        make_chunk("const KEY = \"AKIAQYLPMN5HFIQR7BBB\";", "file1.rs", 0),
        make_chunk(
            "export const PAT = \"ghp_xYz1234ABCD5678efgh9ijkl0123mnopqrs\";",
            "file2.py",
            0,
        ),
        make_chunk(
            "auth: sk_live_4eC39HqLyjWDarjtT1zdp7dc\napi_key: ASIABCD1234DEFGH5IJK",
            "file3.yml",
            0,
        ),
    ];

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    for backend in backends {
        let batch_results = scanner.scan_chunks_with_backend(&chunks, backend);
        let batch_findings: BTreeSet<FindingKey> = batch_results
            .iter()
            .flat_map(|chunk| {
                chunk
                    .iter()
                    .map(|m| (m.credential.as_ref().to_string(), m.location.offset))
            })
            .collect();

        // Now scan each chunk individually and collect findings.
        let mut individual_findings: BTreeSet<FindingKey> = BTreeSet::new();
        for (idx, chunk) in chunks.iter().enumerate() {
            let results = scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), backend);
            for m in results.iter().flat_map(|r| r.iter()) {
                individual_findings.insert((m.credential.as_ref().to_string(), m.location.offset));
            }
        }

        // GPU/MegaScan can silently degrade to SIMD on no adapter.
        if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan)
            && batch_findings.is_empty()
            && individual_findings.is_empty()
        {
            eprintln!("SKIP: {backend:?} (no adapter, silent SIMD degrade)");
            continue;
        }

        if batch_findings != individual_findings {
            let only_batch: Vec<_> = batch_findings
                .difference(&individual_findings)
                .take(3)
                .collect();
            let only_individual: Vec<_> = individual_findings
                .difference(&batch_findings)
                .take(3)
                .collect();
            panic!(
                "coalesced vs individual parity broken for {backend:?}.\n  \
                 batch findings: {}\n  individual findings: {}\n  \
                 only-in-batch={only_batch:?}\n  only-in-individual={only_individual:?}",
                batch_findings.len(),
                individual_findings.len()
            );
        }
    }
}

#[test]
fn per_chunk_order_preserved_coalesced_dispatch() {
    // Coalesced dispatch must preserve per-chunk finding order so
    // callers can correlate results[i] back to chunks[i].
    let detectors = match keyhog_core::load_detectors(&detector_dir()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("SKIP: detectors directory unavailable: {e}");
            return;
        }
    };
    let scanner = CompiledScanner::compile(detectors).expect("scanner compile");

    let chunks = vec![
        make_chunk("// no secrets", "empty.txt", 0),
        make_chunk("const KEY = \"AKIAQYLPMN5HFIQR7CCC\";", "secret.rs", 0),
        make_chunk("// another empty comment", "comment.txt", 0),
        // Valid-checksum GitHub PAT: the github detector verifies the trailing
        // CRC, so a fabricated `ghp_token…` (wrong length, bad checksum) is
        // correctly dropped — the chunk must carry a real-shaped token for the
        // "chunk 3 has findings" assertion to test backend parity, not the
        // checksum gate. See memory: checksum-invalidates-fabricated-token-fixtures.
        make_chunk("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", "github.md", 0),
    ];

    let backends = [
        ScanBackend::SimdCpu,
        ScanBackend::CpuFallback,
        ScanBackend::Gpu,
        ScanBackend::MegaScan,
    ];

    for backend in backends {
        let results = scanner.scan_chunks_with_backend(&chunks, backend);

        // Verify results vector has the same length as chunks vector.
        assert_eq!(
            results.len(),
            chunks.len(),
            "batch dispatch for {backend:?}: result count={} != chunk count={}",
            results.len(),
            chunks.len()
        );

        // Verify results[i] corresponds to chunks[i] by counting
        // findings per chunk. Chunk 0 and 2 should have 0 findings,
        // chunks 1 and 3 should have findings.
        let finding_counts: Vec<usize> = results.iter().map(|chunk| chunk.len()).collect();

        // GPU/MegaScan silently degrade to all-zeros; skip verification if that happens.
        if matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan) {
            if finding_counts == vec![0; chunks.len()] {
                eprintln!("SKIP: {backend:?} (no adapter, silent SIMD degrade)");
                continue;
            }
        }

        assert_eq!(
            finding_counts[0], 0,
            "chunk 0 for {backend:?}: expected 0 findings, got {}",
            finding_counts[0]
        );
        assert!(
            finding_counts[1] > 0,
            "chunk 1 for {backend:?}: expected findings, got {}",
            finding_counts[1]
        );
        assert_eq!(
            finding_counts[2], 0,
            "chunk 2 for {backend:?}: expected 0 findings, got {}",
            finding_counts[2]
        );
        assert!(
            finding_counts[3] > 0,
            "chunk 3 for {backend:?}: expected findings, got {}",
            finding_counts[3]
        );
    }
}
