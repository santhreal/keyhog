//! Honest GPU literal-set throughput measurement on the real detector literal
//! set — the oracle for whether on-GPU scanning can beat the CPU path, and by how
//! much, once the per-dispatch table re-upload is amortized.
//!
//! keyhog's GPU phase-1 calls `GpuLiteralSet::scan()` (the BORROWED path), which
//! `dispatch_borrowed`s the FULL static DFA/prefilter tables on EVERY call
//! (vyre-libs `scan_into_with_program`, buffers 1-9 are static yet re-uploaded).
//! For a 16 KB haystack those tables can exceed the haystack, so per-dispatch the
//! GPU moves `tables + haystack` when only `haystack` changed. This measures:
//!   1. CPU 1-thread  — `reference_scan` over one big batched haystack.
//!   2. GPU big-batch — ONE `scan()` over the same big haystack (table upload
//!      amortized over megabytes → the kernel's throughput ceiling).
//!   3. GPU 16 KB     — many `scan()`s of 16 KB chunks (the re-upload tax exposed
//!      → the per-dispatch overhead the resident API removes).
//! Ratio (2)/(1) is the kernel headroom; (2)/(3) is the size of the resident
//! lever keyhog is leaving on the table.
//!
//! Run (requires the GPU stack):
//!   cargo test --profile release-fast --features gpu -p keyhog-scanner \
//!     --test gpu_resident_throughput -- --ignored --nocapture

#![cfg(feature = "gpu")]

use super::support::paths::{corpus_dir, detector_dir};

use keyhog_scanner::CompiledScanner;
use std::time::Instant;

fn collect_corpus_bytes(limit_bytes: usize) -> Vec<u8> {
    let Some(root) = corpus_dir() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(limit_bytes);
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() {
                if let Ok(b) = std::fs::read(&p) {
                    out.extend_from_slice(&b);
                    out.push(b'\n');
                    if out.len() >= limit_bytes {
                        out.truncate(limit_bytes);
                        return out;
                    }
                }
            }
        }
    }
    out
}

#[test]
#[ignore = "measurement; run with --features gpu --ignored --nocapture"]
fn gpu_literal_set_throughput_vs_cpu() {
    use vyre_driver_wgpu::WgpuBackend;

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let Some(matcher) = scanner.gpu_matcher() else {
        eprintln!("no gpu_matcher (gpu_literals absent); skipping");
        return;
    };
    let backend = match WgpuBackend::shared() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("no wgpu backend ({e}); skipping");
            return;
        }
    };

    // ~16 MiB batched haystack (≈1000 × 16 KiB files coalesced).
    const BIG: usize = 16 * 1024 * 1024;
    let big = collect_corpus_bytes(BIG);
    if big.len() < 1024 * 1024 {
        eprintln!("corpus too small ({} bytes); skipping", big.len());
        return;
    }
    let mb = big.len() as f64 / 1e6;
    let max_matches: u32 = 1_000_000;

    // Warm the GPU (shader compile / first-dispatch init) so it isn't charged to
    // the measured pass.
    let _ = matcher.scan(backend.as_ref(), &big[..1024.min(big.len())], 1024);

    // (1) CPU 1-thread reference over the whole batched haystack.
    let t = Instant::now();
    let cpu_matches = matcher.reference_scan(&big);
    let cpu_ms = t.elapsed().as_secs_f64() * 1000.0;
    let cpu_mbps = mb / (cpu_ms / 1e3);

    // (2) GPU one big dispatch (table upload amortized over 16 MiB).
    let t = Instant::now();
    let gpu_big = matcher
        .scan(backend.as_ref(), &big, max_matches)
        .expect("gpu big scan");
    let gpu_big_ms = t.elapsed().as_secs_f64() * 1000.0;
    let gpu_big_mbps = mb / (gpu_big_ms / 1e3);

    // (3) GPU many 16 KiB dispatches (per-dispatch table re-upload tax exposed).
    let chunk = 16 * 1024;
    let n_chunks = big.len() / chunk;
    let t = Instant::now();
    let mut gpu_small_matches = 0usize;
    for i in 0..n_chunks {
        let slice = &big[i * chunk..(i + 1) * chunk];
        let m = matcher
            .scan(backend.as_ref(), slice, max_matches)
            .expect("gpu 16k scan");
        gpu_small_matches += m.len();
    }
    let gpu_small_ms = t.elapsed().as_secs_f64() * 1000.0;
    let gpu_small_mbps = (n_chunks * chunk) as f64 / 1e6 / (gpu_small_ms / 1e3);

    // (4) GPU COUNT-only on the big haystack — isolates raw scan throughput from
    // match-record append/readback (the dense-match path materializes 66k triples
    // through an atomic counter; count-only writes a single u32).
    let t = Instant::now();
    let gpu_count = matcher.count(backend.as_ref(), &big).expect("gpu count");
    let gpu_count_ms = t.elapsed().as_secs_f64() * 1000.0;
    let gpu_count_mbps = mb / (gpu_count_ms / 1e3);

    // (5) GPU scan on a SPARSE haystack (random-ish bytes, ~no literal hits) —
    // the GPU's scan ceiling with negligible match output.
    let mut sparse = vec![0u8; big.len()];
    for (i, b) in sparse.iter_mut().enumerate() {
        // cheap deterministic pseudo-noise in the printable-but-non-literal range
        *b = b'0' + ((i.wrapping_mul(2654435761) >> 13) % 10) as u8;
    }
    let t = Instant::now();
    let sparse_m = matcher
        .scan(backend.as_ref(), &sparse, max_matches)
        .expect("gpu sparse scan");
    let gpu_sparse_ms = t.elapsed().as_secs_f64() * 1000.0;
    let gpu_sparse_mbps = mb / (gpu_sparse_ms / 1e3);

    eprintln!("\n=== GPU literal-set throughput on {mb:.1} MiB batched corpus ===");
    eprintln!(
        "  (1) CPU 1-thread reference : {cpu_ms:>9.1} ms  {cpu_mbps:>10.1} MB/s  ({} matches)",
        cpu_matches.len()
    );
    eprintln!(
        "  (2) GPU one big dispatch   : {gpu_big_ms:>9.1} ms  {gpu_big_mbps:>10.1} MB/s  ({} matches)",
        gpu_big.len()
    );
    eprintln!(
        "  (3) GPU {n_chunks}×16KiB dispatches : {gpu_small_ms:>9.1} ms  {gpu_small_mbps:>10.1} MB/s  ({gpu_small_matches} matches)"
    );
    eprintln!(
        "  kernel headroom (2)/(1)      = {:.1}×",
        gpu_big_mbps / cpu_mbps.max(1e-9)
    );
    eprintln!(
        "  resident lever (2)/(3)       = {:.1}×  (per-dispatch table re-upload tax)",
        gpu_big_mbps / gpu_small_mbps.max(1e-9)
    );
    eprintln!(
        "  (4) GPU count-only (big)   : {gpu_count_ms:>9.1} ms  {gpu_count_mbps:>10.1} MB/s  ({gpu_count} count)"
    );
    eprintln!(
        "  (5) GPU scan SPARSE (big)  : {gpu_sparse_ms:>9.1} ms  {gpu_sparse_mbps:>10.1} MB/s  ({} matches)",
        sparse_m.len()
    );
    eprintln!(
        "  match-output cost: dense scan {gpu_big_mbps:.1} vs count-only {gpu_count_mbps:.1} vs sparse {gpu_sparse_mbps:.1} MB/s"
    );
}
