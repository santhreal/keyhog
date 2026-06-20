//! Measure the decode-recursion share of a full end-to-end mirror scan — the
//! lever behind the ~0.4 MB/s ceiling that the phase-2 breakdown does NOT
//! capture (it excludes `post_process_matches`' decode-through). Reports total
//! scan wall time vs the time spent rescanning decoded sub-chunks, the
//! sub-chunk count, and the per-sub-chunk fixed cost.
//!
//! Run:
//!   cargo test --profile release-fast -p keyhog-scanner \
//!     --test decode_recursion_profile -- --ignored --nocapture

use super::support::paths::{corpus_dir, corpus_files, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{set_profile_enabled, CompiledScanner, ScanBackend};
use std::time::Instant;

fn chunk_of(bytes: &[u8], label: &str) -> Chunk {
    Chunk {
        data: String::from_utf8_lossy(bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "throughput".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

#[test]
#[ignore = "measurement; run with --ignored --nocapture"]
fn decode_recursion_profile_mirror() {
    set_profile_enabled(true);
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(root) = corpus_dir() else {
        eprintln!("no corpus; skipping");
        return;
    };
    let files = corpus_files(&root, 8000);

    // Regime B: 16 KiB chunks (the headline file-size class).
    let mut chunks_16k: Vec<Vec<u8>> = Vec::new();
    let mut cur = Vec::new();
    for f in &files {
        cur.extend_from_slice(f);
        cur.push(b'\n');
        if cur.len() >= 16 * 1024 {
            chunks_16k.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        chunks_16k.push(cur);
    }
    let bytes16: usize = chunks_16k.iter().map(Vec::len).sum();
    let chunks: Vec<Chunk> = chunks_16k
        .iter()
        .enumerate()
        .map(|(i, c)| chunk_of(c, &format!("16k-{i}")))
        .collect();

    // Warm.
    scanner.clear_fragment_cache();
    for c in &chunks {
        let _ = scanner.scan_chunks_with_backend(std::slice::from_ref(c), ScanBackend::CpuFallback);
    }
    let _ = crate::engine::decode_profile_dump();

    // Measured pass.
    scanner.clear_fragment_cache();
    let t = Instant::now();
    for c in &chunks {
        let _ = scanner.scan_chunks_with_backend(std::slice::from_ref(c), ScanBackend::CpuFallback);
    }
    let total_ms = t.elapsed().as_secs_f64() * 1000.0;

    let _ = crate::engine::phase2_gate_stats_dump();
    crate::engine::scan_inner_profile_dump();
    keyhog_scanner::decode::decoder_profile_dump();
    keyhog_scanner::decode::extract_profile_dump();
    crate::profile_dump("mirror (parents + decode sub-chunks; see decode% column)");
    let (parents, subchunks, sub_bytes, gen_ms, scan_ms) = crate::engine::decode_profile_dump();
    let total_mbps = (bytes16 as f64 / 1e6) / (total_ms / 1e3);
    eprintln!(
        "=== {} 16-KiB chunks ({:.1} MiB) ===",
        chunks.len(),
        bytes16 as f64 / (1024.0 * 1024.0)
    );
    eprintln!("  total scan      {total_ms:>9.1} ms  ({total_mbps:.2} MB/s end-to-end)");
    eprintln!(
        "  decode gen      {gen_ms:>9.1} ms  ({:.1}% of total)",
        100.0 * gen_ms / total_ms
    );
    eprintln!(
        "  decode rescan   {scan_ms:>9.1} ms  ({:.1}% of total)",
        100.0 * scan_ms / total_ms
    );
    eprintln!(
        "  parent scan     {:>9.1} ms  ({:.1}% of total)",
        total_ms - gen_ms - scan_ms,
        100.0 * (total_ms - gen_ms - scan_ms) / total_ms
    );
    eprintln!(
        "  sub-chunks      {subchunks} from {parents} parents ({:.1} sub/parent), {} KiB, {:.2} µs/sub",
        if parents > 0 { subchunks as f64 / parents as f64 } else { 0.0 },
        sub_bytes / 1024,
        if subchunks > 0 { scan_ms * 1000.0 / subchunks as f64 } else { 0.0 },
    );
}
