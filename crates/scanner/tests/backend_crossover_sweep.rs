//! On-demand backend crossover measurement (data source for routing thresholds).
//!
//! `select_backend` (see `hw_probe::thresholds`) routes a scan to GPU once the
//! coalesced buffer clears a tier floor. Those floors must reflect where the GPU
//! *actually* overtakes the CPU paths on real hardware — a number that moved
//! after the always-active phase-2 prefilter fix made the common per-chunk CPU
//! path much cheaper (the old `1–2.5 MiB/s` regime in `perf_floor_matrix` was
//! dominated by 2,730 per-scan phase-2 regexes, now collapsed to one RegexSet
//! pass). This test re-measures the crossover so the thresholds track data.
//!
//! **Why two payload regimes.** The GPU backend accelerates only *phase 1* —
//! the literal/Aho-Corasick prefilter scan. *Phase 2* (regex capture, entropy,
//! ML confidence) runs on the CPU regardless of backend. So:
//!   * **benign-sparse** input (mostly code, rare secrets) is phase-1-bound —
//!     the GPU's parallel scan can beat serial CPU matching at large sizes.
//!     This is the common real-world repo and the regime that sets the floor.
//!   * **hit-dense** input (a credential dump; or keyhog's own secret-corpus)
//!     is phase-2-bound — every byte triggers CPU confirmation, so the GPU adds
//!     dispatch cost on top of identical CPU work and is strictly slower. The
//!     router has no hit-density signal, so the floor must not be so low that a
//!     dense buffer gets sent to a GPU that cannot help it.
//!
//! `#[ignore]`d (a measurement, not a gate) — run explicitly:
//!
//! ```text
//! cargo test -p keyhog-scanner --test backend_crossover_sweep -- --ignored --nocapture
//! ```

mod support;
use support::paths::{corpus_dir, corpus_files, detector_dir};

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::time::Instant;

const KIB: usize = 1024;
const MIB: usize = 1024 * 1024;

/// Benign-sparse sweep points covering the required 8 MiB target and the
/// measured 64 MiB no-win range before the current high-tier heuristic floor.
const BENIGN_SIZES: &[usize] = &[
    256 * KIB,
    512 * KIB,
    1 * MIB,
    2 * MIB,
    4 * MIB,
    8 * MIB,
    16 * MIB,
    32 * MIB,
    64 * MIB,
];

/// Hit-dense is phase-2-bound and ~100× slower per byte, so only small sizes
/// are feasible — just enough to demonstrate the GPU never leads here.
const DENSE_SIZES: &[usize] = &[64 * KIB, 256 * KIB];

/// Timed runs per cell after warm-up; median sheds scheduler/turbo noise.
const TIMED_RUNS: usize = 4;
const TIMED_RUNS_DENSE: usize = 2;

/// One realistic, fixed-shape secret line. Sprinkled sparsely into the benign
/// stream so a *few* phase-2 confirmations happen (as in a real scan) without
/// dominating — models real-world credential density, not a dump.
const SPARSE_SECRET: &str =
    "    let api_token = \"ghp_aaaabbbbccccddddeeeeffff00001111222233\"; // rotate me\n";

/// One benign secret per this many bytes of code (~1 per 64 KiB ≈ a real repo).
const SECRET_EVERY: usize = 64 * KIB;

/// Benign source generator: realistic code tokens (identifiers, keywords,
/// assignments, comments, numbers) with NO secret literal prefixes and no
/// high-entropy blobs, so phase-2 rarely fires. Identifiers vary by a counter
/// so the literal scan does real work over distinct tokens (no degenerate
/// single-token cache effect). One `SPARSE_SECRET` every `SECRET_EVERY` bytes.
fn benign_payload(size: usize) -> String {
    let mut s = String::with_capacity(size + 256);
    let mut counter: u64 = 0;
    let mut since_secret = 0usize;
    while s.len() < size {
        let n = (counter % 97) + 1;
        // A few lines of plausible, secret-free source.
        let unit = format!(
            "fn process_record_{counter}(input: &RecordBatch, ctx: &mut Context) -> Result<usize> {{\n    \
             let total_{counter} = input.rows.iter().map(|r| r.weight * {n}).sum::<u64>();\n    \
             // accumulate partial results for shard {counter} before the reduce step\n    \
             ctx.update_counter(\"shard_{counter}\", total_{counter});\n    \
             Ok(total_{counter} as usize)\n}}\n"
        );
        s.push_str(&unit);
        since_secret += unit.len();
        if since_secret >= SECRET_EVERY {
            s.push_str(SPARSE_SECRET);
            since_secret = 0;
        }
        counter += 1;
    }
    truncate_on_boundary(s, size)
}

/// Build a hit-dense base blob from the mirror corpus (secret-detection
/// fixtures: tiny, secret-packed files). Tiled, this is a worst-case
/// phase-2-bound payload. Lossy-decoded to a valid `String`. `None` if the
/// corpus tree is absent.
fn dense_base() -> Option<String> {
    let root = corpus_dir()?;
    let mut blob = String::with_capacity(MIB);
    for bytes in corpus_files(&root, 4000) {
        if blob.len() >= MIB {
            break;
        }
        blob.push_str(&String::from_utf8_lossy(&bytes));
        blob.push('\n');
    }
    (!blob.is_empty()).then_some(blob)
}

/// Tile `base` to ~`size` bytes, truncating on the nearest char boundary ≤ size.
fn tile(base: &str, size: usize) -> String {
    let mut out = String::with_capacity(size + base.len());
    while out.len() < size {
        out.push_str(base);
    }
    truncate_on_boundary(out, size)
}

fn truncate_on_boundary(mut s: String, size: usize) -> String {
    let mut end = size.min(s.len());
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

fn chunk_of(text: String, label: &str) -> Chunk {
    Chunk {
        data: text.into(),
        metadata: ChunkMetadata {
            source_type: "crossover-sweep".into(),
            path: Some(label.into()),
            base_offset: 0,
            ..Default::default()
        },
    }
}

/// Median MiB/s + total match count for one (backend, chunk) cell. Warms up
/// twice (GPU pays a cold adapter/upload cost on first touch), then times
/// `runs` scans and returns the median rate (on the chunk's *actual* bytes).
fn measure(
    scanner: &CompiledScanner,
    chunk: &Chunk,
    backend: ScanBackend,
    runs: usize,
) -> (f64, usize) {
    // Single warm-up absorbs the GPU cold adapter/upload cost and first-touch
    // allocation; a second adds nothing but wall-clock on the slow large cells.
    let warm = scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), backend);
    let matches: usize = warm.iter().map(Vec::len).sum();

    let mib = chunk.data.len() as f64 / MIB as f64;
    let mut rates = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        let m = scanner.scan_chunks_with_backend(std::slice::from_ref(chunk), backend);
        let secs = start.elapsed().as_secs_f64().max(1e-9);
        std::hint::black_box(&m);
        rates.push(mib / secs);
    }
    rates.sort_by(|a, b| a.partial_cmp(b).unwrap());
    (rates[rates.len() / 2], matches)
}

fn label(size: usize) -> String {
    if size >= MIB {
        format!("{}MiB", size / MIB)
    } else {
        format!("{}KiB", size / KIB)
    }
}

/// Run one labelled sweep over `sizes`, printing a per-size MiB/s table and
/// returning the smallest size at which GPU beats the best CPU backend (if any).
fn sweep(
    scanner: &CompiledScanner,
    name: &str,
    base: &str,
    sizes: &[usize],
    runs: usize,
    gpu_present: bool,
) -> Option<usize> {
    println!("\n--- {name} sweep ---");
    println!(
        "{:>8} | {:>11} | {:>11} | {:>11} | {:>8} | {:>9} | {:>10} | {:>14}",
        "size",
        "cpu MiB/s",
        "simd MiB/s",
        "gpu MiB/s",
        "winner",
        "gpu/best",
        "cpu ns/byte",
        "matches(c/s/g)"
    );
    println!("{}", "-".repeat(104));

    let mut gpu_first_win: Option<usize> = None;
    for &size in sizes {
        let chunk = chunk_of(tile(base, size), &format!("{name}-{}.txt", label(size)));
        let (cpu, cpu_n) = measure(scanner, &chunk, ScanBackend::CpuFallback, runs);
        let (simd, simd_n) = measure(scanner, &chunk, ScanBackend::SimdCpu, runs);
        let (gpu, gpu_n) = if gpu_present {
            measure(scanner, &chunk, ScanBackend::Gpu, runs)
        } else {
            (f64::NAN, 0)
        };

        support::gpu_gate::assert_gpu_not_silent_empty(
            gpu_present && gpu_n == 0,
            simd_n,
            &format!("{name} sweep @ {}", label(size)),
        );

        let best_cpu = cpu.max(simd);
        let winner = if gpu_present && gpu >= best_cpu {
            "gpu"
        } else if simd >= cpu {
            "simd"
        } else {
            "cpu"
        };
        let ratio = if gpu_present && best_cpu > 0.0 {
            gpu / best_cpu
        } else {
            f64::NAN
        };
        if gpu_present && gpu >= best_cpu && gpu_first_win.is_none() {
            gpu_first_win = Some(size);
        }
        let cpu_ns_per_byte = if cpu > 0.0 {
            1.0e9 / (cpu * MIB as f64)
        } else {
            f64::NAN
        };
        println!(
            "{:>8} | {:>11.2} | {:>11.2} | {:>11.2} | {:>8} | {:>8.2}x | {:>10.1} | {:>4}/{:>4}/{:>4}",
            label(size),
            cpu,
            simd,
            gpu,
            winner,
            ratio,
            cpu_ns_per_byte,
            cpu_n,
            simd_n,
            gpu_n
        );
    }
    gpu_first_win
}

#[test]
#[ignore = "measurement, not a gate; run with --ignored --nocapture on a GPU host"]
fn backend_crossover_sweep() {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let gpu_present = keyhog_scanner::gpu::gpu_available();

    println!("\n=== backend crossover sweep ===");
    println!("gpu_present: {gpu_present}");

    // PRIMARY: benign-sparse (phase-1-bound) — this is what sets the GPU floor.
    let benign_base = benign_payload(2 * MIB);
    let gpu_win = sweep(
        &scanner,
        "benign-sparse",
        &benign_base,
        BENIGN_SIZES,
        TIMED_RUNS,
        gpu_present,
    );

    // SECONDARY: hit-dense (phase-2-bound) — demonstrates GPU cannot lead here.
    match dense_base() {
        Some(base) => {
            let _ = sweep(
                &scanner,
                "hit-dense",
                &base,
                DENSE_SIZES,
                TIMED_RUNS_DENSE,
                gpu_present,
            );
        }
        None => println!("\n(hit-dense sweep skipped: mirror corpus absent)"),
    }

    println!("\n{}", "=".repeat(92));
    match gpu_win {
        Some(s) => println!(
            "BENIGN crossover: GPU first beats best-CPU at {} → high-tier GPU_MIN floor target",
            label(s)
        ),
        None if gpu_present => println!(
            "BENIGN crossover: GPU never beat best-CPU up to {} → raise the high-tier GPU floor \
             (GPU not worth it in this range)",
            label(*BENIGN_SIZES.last().unwrap())
        ),
        None => println!("GPU not present — crossover not measured on this host"),
    }
    println!("=== end sweep ===\n");
}

/// Per-detector match counts keyed by detector id, over a flat result set.
fn per_detector(res: &[Vec<keyhog_core::RawMatch>]) -> std::collections::BTreeMap<String, usize> {
    let mut m = std::collections::BTreeMap::new();
    for rm in res.iter().flatten() {
        *m.entry(rm.detector_id.as_ref().to_string()).or_default() += 1;
    }
    m
}

/// Print the detectors where `got` under-counts `reference` (diagnostic on failure).
fn report_detector_loss(
    reference: &[Vec<keyhog_core::RawMatch>],
    got: &[Vec<keyhog_core::RawMatch>],
) {
    let rmap = per_detector(reference);
    let gmap = per_detector(got);
    for (det, c) in &rmap {
        let g = gmap.get(det).copied().unwrap_or(0);
        if g != *c {
            eprintln!(
                "  {det}: reference={c} got={g} (lost {})",
                c.saturating_sub(g)
            );
        }
    }
}

/// GPU-vs-CPU recall parity on a single large buffer (regression guard).
///
/// Guards a fail-open recall gap found on an RTX 5090 (2026-06-06): forcing
/// `--backend gpu` on a benign-sparse 16 MiB buffer returned 496 matches vs the
/// CPU's 744 — it dropped every github-classic-pat (248/248). Root cause was NOT
/// the GPU kernel: the dense literal prefixes (~136k > the 32k AC dispatch cap)
/// make GPU phase-1 reroute to `scan_coalesced`, which scanned the chunk WHOLE
/// and let the per-chunk match cap (`max_matches_per_chunk`, default 1000)
/// silently truncate — github-classic-pat fell past the cap behind the dense
/// generic-assignment hits. Fixed by windowing large triggered chunks in
/// `scan_coalesced` (each 1 MiB window gets its own cap). See the CPU-only
/// `scan_coalesced_large_chunk_matches_windowed_path` for the GPU-free gate.
///
/// `#[ignore]`d (needs a real GPU + a multi-second 16 MiB scan). Run on a GPU host:
///
/// ```text
/// cargo test --release -p keyhog-scanner --test backend_crossover_sweep \
///     gpu_vs_cpu_recall_parity_large_buffer -- --ignored --nocapture
/// ```
#[test]
#[ignore = "GPU-host regression guard; needs a real GPU adapter + a 16 MiB scan"]
fn gpu_vs_cpu_recall_parity_large_buffer() {
    if !keyhog_scanner::gpu::gpu_available() {
        eprintln!("no GPU adapter present; GPU recall parity needs a GPU host");
        return;
    }
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors");
    let scanner = CompiledScanner::compile(detectors).expect("compile");
    let chunk = chunk_of(
        tile(&benign_payload(2 * MIB), 16 * MIB),
        "recall-parity-16MiB.txt",
    );

    let cpu =
        scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback);
    let gpu = scanner.scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::Gpu);
    let cpu_n: usize = cpu.iter().map(Vec::len).sum();
    let gpu_n: usize = gpu.iter().map(Vec::len).sum();

    eprintln!("GPU recall parity @16MiB: cpu={cpu_n} gpu={gpu_n}");
    if gpu_n != cpu_n {
        report_detector_loss(&cpu, &gpu);
    }
    assert!(cpu_n > 0, "CPU reference must find matches");
    assert_eq!(
        gpu_n,
        cpu_n,
        "forced --backend gpu must find the SAME matches as CPU on a {}-byte buffer \
         (gpu={gpu_n} vs cpu={cpu_n}); the GPU dense-prefix reroute lands on scan_coalesced, \
         which must window large chunks so the per-chunk match cap can't truncate.",
        chunk.data.len(),
    );
}

/// CPU-only root-cause gate (runs everywhere, no GPU needed) for the shared
/// windowing contract (`scan_chunk_or_window`).
///
/// Sets a small `max_matches_per_chunk` so the cap would bite at a modest size,
/// then scans a >1 MiB chunk through the bulk `scan_coalesced` path. The exact
/// invariant the windowing fix guarantees: a coalesced scan of a large chunk
/// returns MORE matches than the per-chunk cap — impossible for a single
/// unwindowed scan (which truncates AT the cap), only possible when the chunk is
/// split into windows that each carry their own cap. Pre-fix `scan_coalesced`
/// scanned large chunks whole and capped at ~32; post-fix it windows.
///
/// (Asserting `>cap` rather than exact equality with the per-file path keeps the
/// gate robust: `scan()` additionally runs `post_process_matches` decode
/// recursion that the bulk path deliberately skips, so their totals differ by a
/// few near the cap boundary — a real path divergence, not the bug under test.)
#[test]
fn scan_coalesced_large_chunk_windows_instead_of_capping() {
    const CAP: usize = 32;
    let mut cfg = keyhog_scanner::ScannerConfig::default();
    cfg.max_matches_per_chunk = CAP;
    let scanner =
        CompiledScanner::compile(keyhog_core::load_detectors(&detector_dir()).expect("detectors"))
            .expect("compile")
            .with_config(cfg);

    // 4 MiB → ~4 windows; each window alone exceeds the cap, so an unwindowed
    // whole-chunk scan truncates to ~CAP while the windowed path keeps ~4×.
    let chunk = chunk_of(
        tile(&benign_payload(2 * MIB), 4 * MIB),
        "coalesced-cap-4MiB.txt",
    );

    let coalesced_n: usize = scanner
        .scan_coalesced(std::slice::from_ref(&chunk))
        .iter()
        .map(Vec::len)
        .sum();
    // Sanity: the per-file windowed reference also clears the cap (proves the
    // fixture is dense enough for this gate to mean anything).
    let windowed_n = scanner.scan(&chunk).len();

    eprintln!("large-chunk windowing @4MiB (cap={CAP}): coalesced={coalesced_n} windowed_ref={windowed_n}");
    assert!(
        windowed_n > CAP,
        "windowed reference ({windowed_n}) must exceed the cap ({CAP}) for this gate to be \
         meaningful; raise the payload size if this trips"
    );
    assert!(
        coalesced_n > CAP,
        "scan_coalesced returned {coalesced_n} (<= cap {CAP}) on a 4 MiB chunk: it scanned the \
         chunk WHOLE and the per-chunk match cap silently truncated it. The bulk path must window \
         large chunks via scan_chunk_or_window so each window carries its own cap.",
    );
}
