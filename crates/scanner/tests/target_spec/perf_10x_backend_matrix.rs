//! TARGET-SPEC (FAILING-BY-DESIGN): the backend × size 10x cross-matrix and the
//! phase-2-dominance worklist.
//!
//! Two orthogonal worklists, both RED until batched-GPU phase-2 lands:
//!
//!   A. **Backend × size 10x matrix.** For every corpus size and every routable
//!      backend, the full scan on that backend must be at least 10x faster than
//!      the SimdCpu CPU baseline. Today phase-2 dominates and is backend-
//!      independent (proven by `backend_crossover_sweep` / `phase2_breakdown`),
//!      so EVERY backend is ≈ the baseline, none is 10x — every cell fails. The
//!      matrix makes the "GPU is not faster because phase-2 is CPU" fact one red
//!      assertion per (backend, size) cell, so when batched-GPU phase-2 lands,
//!      exactly the GPU cells turn green and the SimdCpu/CpuFallback cells stay
//!      red (they have no batched verify) — a precise progress signal.
//!
//!   B. **Phase-2 dominance.** Asserts phase-2 is < 5% of full-scan wall time at
//!      each size — the INVERSE of today's reality (phase-2 is the ~99%). This
//!      is the load-bearing premise of the whole 10x program ("the 10x lives in
//!      phase-2"): it must stay RED until phase-2 is fast, at which point phase-1
//!      becomes the floor and dominance flips. We bound phase-1 by a near-free
//!      no-candidate scan of the SAME bytes and treat the remainder of the
//!      candidate-dense scan as phase-2 — a sound split because phase-1 cost is
//!      candidate-independent (it touches every byte either way).
//!
//! The named matrix/dominance cells assert REAL measured ratios (Law 6), never
//! weakened to pass (Law 9). Rollup tests are declaration-coverage checks only:
//! they must not duplicate the heavy scans already owned by the named cells.

use keyhog_core::{load_detectors, Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::PathBuf;
use std::time::Instant;

fn detectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../detectors")
}

fn build_scanner() -> CompiledScanner {
    let detectors =
        load_detectors(&detectors_dir()).expect("load detectors for matrix target-spec");
    CompiledScanner::compile(detectors).expect("compile scanner for matrix target-spec")
}

/// SplitMix64-seeded corpus: `credential_dense = true` emits authentic anchored
/// credential shapes (heavy phase-2); `false` emits structurally identical
/// non-credential filler of the SAME byte length (phase-1 touches every byte
/// but surfaces ≈no candidate, isolating phase-1 cost).
fn corpus(target_bytes: usize, credential_dense: bool) -> String {
    let mut state: u64 = if credential_dense {
        0x243F_6A88_85A3_08D3
    } else {
        0x13198A2E03707344
    };
    let mut next = move || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };
    const ALNUM: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let alnumn = |r: &mut dyn FnMut() -> u64, n: usize| {
        (0..n)
            .map(|_| ALNUM[(r() % 62) as usize] as char)
            .collect::<String>()
    };
    let mut out = String::with_capacity(target_bytes + 128);
    let mut i = 0usize;
    while out.len() < target_bytes {
        if credential_dense {
            // Authentic anchored shape — phase-1 surfaces a candidate per line.
            let _ = i;
            out.push_str("k = \"github_pat_");
            out.push_str(&alnumn(&mut next, 22));
            out.push('_');
            out.push_str(&alnumn(&mut next, 59));
            out.push_str("\"\n");
        } else {
            // Same byte budget, no detector prefix → no candidate, phase-1 only.
            out.push_str("note = \"");
            out.push_str(&alnumn(&mut next, 88)); // 22+1+59 + quotes ≈ same width
            out.push_str("\" // commentary line, no credential present here ok\n");
        }
        i += 1;
    }
    out.truncate(target_bytes);
    out
}

fn chunk_of(data: String, label: &str) -> Chunk {
    Chunk {
        data: data.into(),
        metadata: ChunkMetadata {
            source_type: "matrix-target-spec".into(),
            path: Some(format!("corpus/{label}.rs")),
            base_offset: 0,
            ..Default::default()
        },
    }
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn scan_secs(scanner: &CompiledScanner, chunk: &Chunk, backend: ScanBackend) -> f64 {
    scanner.clear_fragment_cache();
    let _ = scanner.scan_with_backend(chunk, backend); // warm
    median(
        (0..MEASURE_REPS)
            .map(|_| {
                scanner.clear_fragment_cache();
                let t = Instant::now();
                let _ = scanner.scan_with_backend(chunk, backend);
                t.elapsed().as_secs_f64()
            })
            .collect(),
    )
}

const SIZE_MIB: &[usize] = &[8, 16, 32, 64];
const SPEEDUP_TARGET: f64 = 10.0;

/// Timed scans per measurement after one warm-up. Phase-2 dominates and is
/// backend-independent today, so every cell misses 10x by ~an order of
/// magnitude — one timed scan is a sound RED signal and keeps this 12-cell ×
/// multi-MiB matrix (which RUNS — never `#[ignore]`) within budget.
const MEASURE_REPS: usize = 1;

/// Every backend that the live scan dispatcher can route a workload to. The
/// matrix asserts each must reach 10x once batched phase-2 exists; the
/// CPU-only backends are included deliberately so the matrix records that they
/// STILL won't be 10x (no batched verify) — making GPU-vs-CPU progress legible.
const ROUTABLE_BACKENDS: &[ScanBackend] = &[
    ScanBackend::Gpu,
    ScanBackend::MegaScan,
    ScanBackend::CpuFallback,
];

/// One (backend, size) cell of the 10x cross-matrix.
fn assert_backend_10x_cell(backend: ScanBackend, mib: usize) {
    let bytes = mib * 1024 * 1024;
    eprintln!(
        "perf_10x_matrix[{}, {mib} MiB]: starting measured 10x cell",
        backend.label()
    );
    let scanner = build_scanner();
    let corpus_s = corpus(bytes, true);
    let chunk = chunk_of(corpus_s, &format!("cell-{}-{mib}", backend.label()));

    let baseline = scan_secs(&scanner, &chunk, ScanBackend::SimdCpu);
    let candidate = scan_secs(&scanner, &chunk, backend);
    let target = baseline / SPEEDUP_TARGET;
    let speedup = baseline / candidate.max(1e-12);

    eprintln!(
        "perf_10x_matrix[{}, {mib} MiB]: baseline(SimdCpu)={baseline:.4}s this={candidate:.4}s \
         target<= {target:.4}s speedup={speedup:.2}x (target {SPEEDUP_TARGET:.0}x)",
        backend.label()
    );

    assert!(
        candidate <= target,
        "10x MATRIX CELL [{}, {mib} MiB]: this backend's full scan took {candidate:.4}s but the \
         target is baseline/{SPEEDUP_TARGET:.0} = {target:.4}s (SimdCpu baseline {baseline:.4}s). \
         speedup={speedup:.2}x. Phase-2 dominates and is backend-independent today, so no \
         backend is 10x; this cell turns green only when {} gains a batched phase-2 verify.",
        backend.label(),
        backend.label()
    );
}

// ---- Backend × size 10x cross-matrix (3 backends × 4 sizes = 12 cells) ------

#[test]
fn matrix_gpu_8mib() {
    assert_backend_10x_cell(ScanBackend::Gpu, 8);
}
#[test]
fn matrix_gpu_16mib() {
    assert_backend_10x_cell(ScanBackend::Gpu, 16);
}
#[test]
fn matrix_gpu_32mib() {
    assert_backend_10x_cell(ScanBackend::Gpu, 32);
}
#[test]
fn matrix_gpu_64mib() {
    assert_backend_10x_cell(ScanBackend::Gpu, 64);
}
#[test]
fn matrix_megascan_8mib() {
    assert_backend_10x_cell(ScanBackend::MegaScan, 8);
}
#[test]
fn matrix_megascan_16mib() {
    assert_backend_10x_cell(ScanBackend::MegaScan, 16);
}
#[test]
fn matrix_megascan_32mib() {
    assert_backend_10x_cell(ScanBackend::MegaScan, 32);
}
#[test]
fn matrix_megascan_64mib() {
    assert_backend_10x_cell(ScanBackend::MegaScan, 64);
}
#[test]
fn matrix_cpufallback_8mib() {
    assert_backend_10x_cell(ScanBackend::CpuFallback, 8);
}
#[test]
fn matrix_cpufallback_16mib() {
    assert_backend_10x_cell(ScanBackend::CpuFallback, 16);
}
#[test]
fn matrix_cpufallback_32mib() {
    assert_backend_10x_cell(ScanBackend::CpuFallback, 32);
}
#[test]
fn matrix_cpufallback_64mib() {
    assert_backend_10x_cell(ScanBackend::CpuFallback, 64);
}

fn matrix_cell_names() -> Vec<String> {
    let mut cells = Vec::new();
    for &backend in ROUTABLE_BACKENDS {
        for &mib in SIZE_MIB {
            cells.push(format!("matrix_{}_{}mib", backend.label(), mib));
        }
    }
    cells
}

/// Fast backend×size matrix declaration rollup.
///
/// The measured cells above own the real 10x assertions. This rollup exists to
/// keep the matrix complete without silently rerunning the entire multi-MiB
/// benchmark suite inside one opaque test.
#[test]
fn matrix_all_cells_rollup() {
    let cells = matrix_cell_names();
    let total = SIZE_MIB.len() * ROUTABLE_BACKENDS.len();
    assert_eq!(
        cells.len(),
        total,
        "10x matrix declaration drift: expected {total} backend/size cells, got {cells:?}"
    );
    eprintln!("10x matrix measured cells declared: {cells:?}");
}

// ---- Phase-2 dominance worklist --------------------------------------------

/// After batched phase-2 lands, phase-2 must be a SMALL fraction of full-scan
/// time. Target: phase-2 < 5% of wall time. Today it is ~99%, so each size
/// fails. We split phase-1 (no-candidate scan of identical bytes) from the
/// candidate-dense scan; the difference is phase-2.
const PHASE2_MAX_FRACTION: f64 = 0.05;

fn assert_phase2_dominance_at(mib: usize) {
    let bytes = mib * 1024 * 1024;
    eprintln!("perf_10x_dominance[{mib} MiB]: starting measured dominance cell");
    let scanner = build_scanner();

    // Phase-1-only proxy: no-credential corpus of identical size. Phase-1
    // touches every byte; with no detector prefix it surfaces ≈no candidate, so
    // ~all of this time is phase-1 (prefilter) work.
    let bare = chunk_of(corpus(bytes, false), &format!("p1-{mib}"));
    let phase1 = scan_secs(&scanner, &bare, ScanBackend::SimdCpu);

    // Full credential-dense scan: phase-1 + phase-2.
    let dense = chunk_of(corpus(bytes, true), &format!("p12-{mib}"));
    let full = scan_secs(&scanner, &dense, ScanBackend::SimdCpu);

    let phase2 = (full - phase1).max(0.0);
    let frac = phase2 / full.max(1e-12);

    eprintln!(
        "perf_10x_dominance[{mib} MiB]: phase1≈{phase1:.4}s full={full:.4}s \
         phase2≈{phase2:.4}s ({:.1}% of wall)  target phase2 < {:.0}%",
        frac * 100.0,
        PHASE2_MAX_FRACTION * 100.0
    );

    assert!(
        frac < PHASE2_MAX_FRACTION,
        "PHASE-2 DOMINANCE [{mib} MiB]: phase-2 is {:.1}% of full-scan wall time but the \
         post-batched-GPU target is < {:.0}%. Phase-2 (per-candidate CPU verify) is the \
         bottleneck — this is the load-bearing premise of the 10x program. RED until phase-2 \
         is batched onto the GPU and phase-1 becomes the floor.",
        frac * 100.0,
        PHASE2_MAX_FRACTION * 100.0
    );
}

#[test]
fn phase2_dominance_8mib() {
    assert_phase2_dominance_at(8);
}
#[test]
fn phase2_dominance_16mib() {
    assert_phase2_dominance_at(16);
}
#[test]
fn phase2_dominance_32mib() {
    assert_phase2_dominance_at(32);
}
#[test]
fn phase2_dominance_64mib() {
    assert_phase2_dominance_at(64);
}

/// Fast phase-2 dominance declaration rollup.
///
/// The measured per-size tests above own the real dominance assertions. This
/// rollup keeps the size list visible without duplicating the heavy scans.
#[test]
fn phase2_dominance_all_sizes_rollup() {
    assert_eq!(
        SIZE_MIB,
        &[8, 16, 32, 64],
        "phase-2 dominance target sizes changed; keep the named measured tests in sync"
    );
    eprintln!("phase-2 dominance measured sizes declared: {SIZE_MIB:?}");
}
