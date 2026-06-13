//! Regression: the production coalesced scan path MUST run the line-based
//! cross-chunk fragment reassembly (`:reassembled`) the per-chunk `scan` API
//! runs.
//!
//! The CLI orchestrator (`orchestrator/dispatch.rs`) scans every batch through
//! `scan_coalesced` (CPU) or `scan_chunks_with_backend(.., Gpu)` (GPU) — BOTH
//! feed the shared `scan_coalesced_phase2` tail. That tail historically ran
//! per-chunk extraction (`scan_prepared_with_triggered`) but NOT the
//! `scan_cross_chunk_fragments` join that stitches a secret split across two
//! assignment lines/chunks of one file into a single `:reassembled` finding.
//! The per-chunk `scan` API runs it (inside `post_process_matches`); the
//! boundary seam scan also runs it via `scanner.scan()`, which masked the hole
//! for split secrets at a window seam — but a batch of separate-chunk fragments
//! surfaced nothing on the coalesced path. A silent recall drop on every real
//! `keyhog scan` (Law 10), pinned for the GPU path by the integration test
//! `gpu_batch_preserves_cross_chunk_reassembly`; this pins it for the CPU
//! coalesced path so the contract is backend-independent.

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn chunk(text: &str, path: &str) -> Chunk {
    Chunk {
        data: text.to_string().into(),
        metadata: ChunkMetadata {
            source_type: "regression".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    }
}

/// Two assignment fragments of the same secret in separate chunks of one batch
/// must reassemble into a `:reassembled` finding on the coalesced path, the same
/// join `post_process_matches` produces on the per-chunk path. Mirrors the GPU
/// integration test `gpu_batch_preserves_cross_chunk_reassembly` on the CPU
/// coalesced path so the contract is backend-independent.
#[test]
fn coalesced_reassembles_cross_chunk_fragments() {
    // Custom detector whose pattern matches ONLY the reassembled value
    // (`abcde` + 15 chars of [0-9A-Z]) — neither fragment matches alone, so a
    // `:reassembled` finding can only come from the cross-chunk fragment join.
    let scanner = CompiledScanner::compile(vec![DetectorSpec {
        id: "demo-reassembled-token".into(),
        name: "Demo Reassembled Token".into(),
        service: "demo".into(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: "abcde[0-9A-Z]{15}".into(),
            description: None,
            group: None,
            client_safe: false,
        }],
        keywords: vec!["api_key".into()],
        ..Default::default()
    }])
    .expect("compile demo scanner");

    let chunks = vec![
        chunk("api_key_part1 = \"abcde12345\"", "frag.env"),
        chunk("api_key_part2 = \"FGHIJ67890\"", "frag.env"),
    ];

    let coalesced = scanner.scan_coalesced(&chunks);
    let coalesced_reassembled = coalesced
        .iter()
        .flatten()
        .filter(|m| m.detector_id.as_ref().ends_with(":reassembled"))
        .count();

    assert!(
        coalesced_reassembled >= 1,
        "scan_coalesced must produce a :reassembled finding for the cross-chunk \
         fragment join (abcde12345 + FGHIJ67890 -> abcde12345FGHIJ67890); got {} \
         — the line-based fragment join was dropped on the coalesced tail",
        coalesced_reassembled
    );
}
