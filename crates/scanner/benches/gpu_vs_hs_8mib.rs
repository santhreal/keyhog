//! Apples-to-apples 8 MiB baseline: Hyperscan/SimdCpu vs the GPU megakernel.
//!
//! Same `CompiledScanner` (real detector catalog), same single 8 MiB chunk,
//! same `scan_chunks_with_backend` batch entry. `SimdCpu` runs the Hyperscan
//! literal prefilter phase-1; `Gpu` routes the batch through
//! `scan_coalesced_megakernel` (the vyre batched-DFA megakernel). Both share
//! `scan_coalesced_phase2`, so the delta is phase-1 backend only.
//!
//! Pass `-- --perf-trace` to get the megakernel's internal phase breakdown
//! (catalog / coalesce / dispatch / validate / phase2) and the vyre dispatch
//! telemetry (bytes uploaded / read back / kernel launches) on stderr.
//!
//! This is a plain `main()` (harness = false) so the numbers are raw wall-time
//! medians, not criterion's adaptive sampling — every number is one timed call.

use keyhog_core::{load_detectors, Chunk, ChunkMetadata};
use keyhog_scanner::{set_perf_trace_enabled, CompiledScanner, ScanBackend};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MIB: usize = 1024 * 1024;

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn make_chunk(data: String, path: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "benchmark".into(),
            path: Some(path.into()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            ..Default::default()
        },
    }
}

/// Realistic source-like text with a sparse real hit every ~64 KiB, so phase-2
/// runs on a few candidate windows (the common scan shape) rather than either
/// extreme (all-hit dense / zero-hit). 8 MiB total.
fn gen_payload(size: usize) -> String {
    let filler = "fn ordinary_function() { let x = compute_value(42); println!(\"{}\", x); }\n";
    let secret = "const api_key = \"sk_live_0123456789abcdefghijklmnopqrstuv\";\n";
    let mut s = String::with_capacity(size + 128);
    let mut since_secret = 0usize;
    while s.len() < size {
        if since_secret >= 64 * 1024 {
            s.push_str(secret);
            since_secret = 0;
        } else {
            s.push_str(filler);
            since_secret += filler.len();
        }
    }
    s.truncate(size);
    s
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn time_backend(
    scanner: &CompiledScanner,
    chunks: &[Chunk],
    backend: ScanBackend,
    iters: usize,
) -> (Duration, usize) {
    // Warm: first GPU call pays the one-time catalog upload + pipeline compile;
    // first SimdCpu call warms caches. Exclude it from the steady-state median.
    let warm = scanner.scan_chunks_with_backend(chunks, backend);
    let hits: usize = warm.iter().map(Vec::len).sum();
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        let r = scanner.scan_chunks_with_backend(chunks, backend);
        samples.push(t.elapsed());
        std::hint::black_box(&r);
    }
    (median(samples), hits)
}

fn report(label: &str, d: Duration, bytes: usize, hits: usize) {
    let ms = d.as_secs_f64() * 1e3;
    let gbps = bytes as f64 / d.as_secs_f64() / 1e9;
    println!("{label:<28} {ms:>10.4} ms   {gbps:>8.3} GB/s   hits={hits}",);
}

fn main() {
    let perf_trace = std::env::args().any(|arg| arg == "--perf-trace");
    set_perf_trace_enabled(perf_trace);

    let size: usize = std::env::var("KH_BENCH_SIZE_MIB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8)
        * MIB;
    let iters: usize = std::env::var("KH_BENCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    let detectors = load_detectors(&detectors_dir()).expect("load detectors");
    let n_det = detectors.len();
    let scanner = CompiledScanner::compile(detectors).expect("compile scanner");

    let payload = gen_payload(size);
    let chunk = make_chunk(payload, "src/bench_8mib.rs");
    let chunks = vec![chunk];

    println!("=== keyhog 8 MiB matching baseline (GPU megakernel vs Hyperscan/SimdCpu) ===");
    println!(
        "input={} MiB  detectors={}  iters={}  (median of {} steady-state calls, 1 warm-up excluded)",
        size / MIB,
        n_det,
        iters,
        iters
    );
    println!(
        "{:<28} {:>13}   {:>13}   hits",
        "backend", "wall (median)", "throughput"
    );

    // SimdCpu / Hyperscan phase-1 path.
    let (hs, hs_hits) = time_backend(&scanner, &chunks, ScanBackend::SimdCpu, iters);
    report("SimdCpu (Hyperscan)", hs, size, hs_hits);

    // GPU megakernel path. --perf-trace prints the internal phase breakdown
    // from megakernel_dispatch.rs plus the vyre dispatch telemetry.
    #[cfg(feature = "gpu")]
    {
        // Surface the live GPU backend label so a silent degrade is visible.
        if let Some(lbl) = scanner.runtime_status().gpu_backend {
            println!("(gpu backend: {lbl})");
        } else {
            println!("(gpu backend: NONE acquired — Gpu path will degrade loudly)");
        }
        let (gpu, gpu_hits) = time_backend(&scanner, &chunks, ScanBackend::Gpu, iters);
        report("Gpu (vyre megakernel)", gpu, size, gpu_hits);
        let status = scanner.runtime_status();
        if status.gpu_degrade_count > 0 {
            println!(
                "!! GPU degraded during scan; count={}",
                status.gpu_degrade_count
            );
        }
        let ratio = gpu.as_secs_f64() / hs.as_secs_f64();
        println!(
            "\nGPU / Hyperscan wall ratio = {ratio:.2}x  ({})",
            if ratio > 1.0 {
                "GPU SLOWER"
            } else {
                "GPU faster"
            }
        );
        assert_eq!(
            gpu_hits, hs_hits,
            "recall parity broken: GPU={gpu_hits} hits, Hyperscan={hs_hits} hits on the same 8 MiB input"
        );
    }
    #[cfg(not(feature = "gpu"))]
    {
        println!("(gpu feature OFF — build with --features gpu for the GPU comparison)");
    }
}
