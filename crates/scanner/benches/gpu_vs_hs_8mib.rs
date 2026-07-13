//! Apples-to-apples 8 MiB baseline: Hyperscan/SimdCpu vs GPU region presence.
//!
//! Same `CompiledScanner` (real detector catalog), same production-style 1 MiB
//! windows with 128 KiB overlap over an 8 MiB file, same
//! `scan_chunks_with_backend` entry. The layout lets the Hyperscan path use its
//! real Rayon parallelism instead of handicapping it behind one oversized
//! sequential chunk. `SimdCpu`
//! runs the Hyperscan literal prefilter; `Gpu` routes the batch through Vyre
//! `GpuLiteralSet::scan_presence_by_region_with_scratch`. Timing includes each
//! backend's production batching, scheduling, phase 2, and post-processing.
//!
//! Pass `-- --perf-trace` to get the region-presence phase breakdown
//! (matcher / coalesce / dispatch / floor / phase2_gpu / phase2) and Vyre
//! dispatch telemetry on stderr. Trace instrumentation is intentionally not a
//! crossover measurement: it adds GPU-specific timers and counters, so the
//! speed gate is enforced only by the normal untraced run. Full-result parity
//! remains mandatory in both modes.
//!
//! This is a plain `main()` (harness = false) so the numbers are raw wall-time
//! medians, not criterion's adaptive sampling (every number is one timed call).

use keyhog_core::{load_detectors, Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{
    set_perf_trace_enabled, set_profile_enabled, CompiledScanner, ScanBackend, ScannerTuningConfig,
};
use std::env;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MIB: usize = 1024 * 1024;
const WINDOW_OVERLAP: usize = 128 * 1024;

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn make_chunk(data: String, path: &str, base_offset: usize, base_line: usize) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            base_offset,
            base_line,
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

fn make_chunks(data: String, chunk_bytes: usize, overlap: usize) -> Vec<Chunk> {
    assert!(chunk_bytes > overlap, "window must exceed overlap");
    let stride = chunk_bytes - overlap;
    let mut chunks = Vec::with_capacity(data.len().div_ceil(stride));
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + chunk_bytes).min(data.len());
        let chunk = &data[offset..end];
        let base_line = data.as_bytes()[..offset]
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count();
        chunks.push(make_chunk(
            chunk.to_owned(),
            "src/bench_8mib.rs",
            offset,
            base_line,
        ));
        if end == data.len() {
            break;
        }
        offset += stride;
    }
    chunks
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

fn canonicalize_results(results: &mut [Vec<RawMatch>]) {
    for matches in results {
        matches.sort();
    }
}

fn time_backend(
    label: &str,
    scanner: &CompiledScanner,
    chunks: &[Chunk],
    backend: ScanBackend,
    iters: usize,
    profile: bool,
) -> (Duration, Vec<Vec<RawMatch>>) {
    // Warm: first GPU call pays the one-time catalog upload + pipeline compile;
    // first SimdCpu call warms caches. Exclude it from the steady-state median.
    scanner.clear_fragment_cache();
    let mut warm = scanner.scan_chunks_with_backend(chunks, backend);
    canonicalize_results(&mut warm);
    if profile {
        scanner.reset_profile_reports();
    }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        // The fragment cache is scan-operation state used for cross-file
        // reassembly. Reusing it across logical benchmark scans changes results
        // and does not model a fresh production scan over this workload.
        scanner.clear_fragment_cache();
        let t = Instant::now();
        let mut r = scanner.scan_chunks_with_backend(chunks, backend);
        samples.push(t.elapsed());
        canonicalize_results(&mut r);
        if r != warm {
            let chunk_index = r
                .iter()
                .zip(&warm)
                .position(|(actual, expected)| actual != expected)
                .map_or_else(|| r.len().min(warm.len()), |index| index);
            let actual = r.get(chunk_index);
            let expected = warm.get(chunk_index);
            panic!(
                "{label} produced nondeterministic full finding results across timed calls: \
                 first differing chunk={chunk_index}, actual={actual:?}, expected={expected:?}"
            );
        }
        std::hint::black_box(&r);
    }
    if profile {
        scanner.dump_profile_reports(label);
    }
    (median(samples), warm)
}

fn hit_count(results: &[Vec<RawMatch>]) -> usize {
    results.iter().map(Vec::len).sum()
}

fn report(label: &str, d: Duration, bytes: usize, hits: usize) {
    let ms = d.as_secs_f64() * 1e3;
    let gbps = bytes as f64 / d.as_secs_f64() / 1e9;
    println!("{label:<28} {ms:>10.4} ms   {gbps:>8.3} GB/s   hits={hits}",);
}

fn env_positive_usize(name: &str, default: usize) -> Result<usize, io::Error> {
    match env::var(name) {
        Ok(raw) => {
            let value = raw.parse::<usize>().map_err(|source| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name}={raw:?} must be a positive integer: {source}"),
                )
            })?;
            if value == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{name} must be greater than zero"),
                ));
            }
            Ok(value)
        }
        Err(env::VarError::NotPresent) => Ok(default),
        Err(env::VarError::NotUnicode(raw)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not valid Unicode: {raw:?}"),
        )),
    }
}

fn env_optional_bool(name: &str) -> Result<Option<bool>, io::Error> {
    match env::var(name) {
        Ok(raw) => match raw.as_str() {
            "1" | "true" | "on" | "yes" => Ok(Some(true)),
            "0" | "false" | "off" | "no" => Ok(Some(false)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name}={raw:?} must be one of 1/0, true/false, on/off, or yes/no"),
            )),
        },
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(raw)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} is not valid Unicode: {raw:?}"),
        )),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let perf_trace = args.iter().any(|arg| arg == "--perf-trace");
    let profile = args.iter().any(|arg| arg == "--profile");
    set_perf_trace_enabled(perf_trace);
    set_profile_enabled(profile);

    let size_mib = env_positive_usize("KH_BENCH_SIZE_MIB", 8)?;
    let size = size_mib.checked_mul(MIB).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{size_mib} MiB overflows usize on this host"),
        )
    })?;
    let iters = env_positive_usize("KH_BENCH_ITERS", 20)?;

    let detectors = load_detectors(&detectors_dir())?;
    let n_det = detectors.len();
    let confirmed_suffix_gate = env_optional_bool("KH_BENCH_CONFIRMED_SUFFIX_GATE")?;
    let tuning = ScannerTuningConfig {
        confirmed_suffix_gate,
        ..ScannerTuningConfig::default()
    };
    let scanner = CompiledScanner::compile(detectors)?.with_tuning_config(tuning);

    let payload = gen_payload(size);
    let chunks = make_chunks(payload, MIB, WINDOW_OVERLAP);

    assert!(
        scanner.warm_backend(ScanBackend::SimdCpu),
        "Hyperscan/SimdCpu is unavailable; refusing to benchmark a CPU fallback"
    );
    #[cfg(feature = "gpu")]
    assert!(
        scanner.warm_backend(ScanBackend::Gpu),
        "GPU region-presence backend is unavailable; refusing to benchmark a CPU fallback"
    );

    println!("=== keyhog 8 MiB matching baseline (GPU region presence vs Hyperscan/SimdCpu) ===");
    let status = scanner.runtime_status();
    println!(
        "input={} MiB  chunks={}  detectors={}  gpu_backend={}  host_threads={}  iters={}  (median of {} steady-state calls, 1 warm-up excluded)",
        size / MIB,
        chunks.len(),
        n_det,
        status.gpu_backend.map_or("none", |backend| backend),
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get),
        iters,
        iters
    );
    if let Some(enabled) = confirmed_suffix_gate {
        println!("confirmed_suffix_gate={enabled}");
    }
    println!(
        "{:<28} {:>13}   {:>13}   hits",
        "backend", "wall (median)", "throughput"
    );

    // SimdCpu / Hyperscan phase-1 path.
    let (hs, hs_results) = time_backend(
        "bench-simd-hyperscan",
        &scanner,
        &chunks,
        ScanBackend::SimdCpu,
        iters,
        profile,
    );
    let hs_hits = hit_count(&hs_results);
    report("SimdCpu (Hyperscan)", hs, size, hs_hits);

    // GPU region-presence path. --perf-trace prints the internal phase
    // breakdown plus Vyre dispatch telemetry.
    #[cfg(feature = "gpu")]
    {
        let degrade_before = scanner.gpu_degrade_count();
        let (gpu, gpu_results) = time_backend(
            "bench-gpu-region",
            &scanner,
            &chunks,
            ScanBackend::Gpu,
            iters,
            profile,
        );
        let gpu_hits = hit_count(&gpu_results);
        report("Gpu (region presence)", gpu, size, gpu_hits);
        let status = scanner.runtime_status();
        assert_eq!(
            status.gpu_degrade_count, degrade_before,
            "GPU degraded during the measured run; refusing to report fallback timing as GPU"
        );
        let ratio = gpu.as_secs_f64() / hs.as_secs_f64();
        println!(
            "\nGPU / Hyperscan wall ratio = {ratio:.2}x  ({})",
            if ratio > 1.0 {
                "GPU SLOWER"
            } else {
                "GPU faster"
            }
        );
        assert!(
            gpu_results == hs_results,
            "exact parity broken: GPU and Hyperscan returned different full RawMatch results on the same 8 MiB input (GPU hits={gpu_hits}, Hyperscan hits={hs_hits})"
        );
        if perf_trace {
            println!(
                "crossover gate not enforced under --perf-trace; trace instrumentation is diagnostic and GPU-specific. Rerun without --perf-trace for the production speed gate."
            );
        } else {
            assert!(
                gpu < hs,
                "8 MiB crossover missed: GPU median {gpu:?} did not beat the fastest Hyperscan median {hs:?}"
            );
        }
    }
    #[cfg(not(feature = "gpu"))]
    {
        println!("(gpu feature OFF, build with --features gpu for the GPU comparison)");
    }
    Ok(())
}
