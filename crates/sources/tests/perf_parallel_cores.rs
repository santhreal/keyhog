//! PERF tripwire (KEY: parallel_cores) — multicore scaling of the many-small-
//! files ingestion hot path, `keyhog_sources::FilesystemSource::chunks()`.
//!
//! HOT PATH & WHY THIS FILE EXISTS
//! -------------------------------
//! `keyhog scan <dir>` of a tree of many small files routes EVERY chunk through
//! `FilesystemSource::chunks()` before any scanning happens. Both CLI scan
//! pipelines consume that one iterator:
//!   * the fused path (`crates/cli/src/orchestrator/dispatch.rs:570`,
//!     `scan_sources_fused`) — a single drain thread bridges the `!Send`
//!     `chunks()` iterator into a `sync_channel`, then `par_bridge()` scans;
//!   * the legacy path (`dispatch.rs:200` `scan_sources`) — same `chunks()`,
//!     one scanner thread.
//!
//! `FilesystemSource::chunks()` spawns its OWN dedicated rayon reader pool
//! (`crates/sources/src/filesystem.rs:322-326`) sized by
//! `reader_pool_thread_count(scan_threads) = clamp(scan_threads/2, 2, 16)`
//! (`filesystem.rs:70-74`). That pool is SEPARATE from the global rayon pool
//! the consumer scans on, so on an N-core host configured with N scan threads
//! the process runs **N scan threads + clamp(N/2,2,16) reader threads** — e.g.
//! 16 scan + 8 reader = 24 threads contending for 16 cores (50% oversubscribed),
//! or 32 scan + 16 reader = 48 threads on 16 cores (3x). The OS deschedules
//! scan workers in favour of reader threads, so the consumer can never reach
//! the parallel speedup the same work reaches when fed off a pre-read buffer.
//!
//! MEASURED (release profile, AMD Ryzen 9 9950X, 16 physical / 32 logical,
//! 2026-06-02; 4000 ~1KB files; this test's own A-vs-B harness, best-of-4 min):
//!
//!   (B) representative per-chunk work over a PRE-READ Vec<Chunk>:  ~15.3x @ 16t
//!       (the achievable ceiling — `par_iter` over an owned slice scales near-
//!        linearly to physical cores)
//!   (A) the SAME work driven through `FilesystemSource::chunks()` exactly as
//!       `scan_sources_fused` does (drain bridge -> sync_channel(fused_depth)
//!       -> par_bridge -> work):                                    ~9.9x  @ 16t
//!
//!   source-path parallel efficiency = A_speedup / B_speedup ≈ 9.9 / 15.3
//!                                    ≈ 0.65  (the source loses ~35% of the
//!                                    machine's achievable scaling).
//!
//! This reproduces, in-process, the end-to-end cap a black-box run shows on the
//! shipped `release-fast` binary: the `scan_sources_fused` PHASE wall for the
//! same 4000-file corpus goes 1t=1.56s -> 16t=0.33s (only **4.7x**, vs the
//! 9.7x the scan engine `CompiledScanner::scan_coalesced` reaches on a flat
//! slice) and REGRESSES at 32t (719ms > 626ms@16t) as the reader pool grows to
//! 16 and oversubscription hits 3x. The scan engine and the fused-dispatch
//! shape both scale to ~9-10x in isolation (verified separately), so the cap is
//! upstream, in this crate's chunk-production path — which is why this tripwire
//! lives in `keyhog-sources`, not the scanner.
//!
//! FIX (landed) & what this floor now guards
//! -----------------------------------------
//! The reader no longer runs as a second full pool that double-counts cores
//! against the consumer: `reader_thread_count` is a small FIXED crew (~scan/4,
//! capped at `MAX_READER_THREADS` = 4, floored at 2) that never scales with the
//! scan pool (the deterministic, host-independent proof lives in
//! `tests/unit/filesystem.rs`). That lifted realized efficiency from ~0.48
//! (oversubscribed) to ~0.72. The residual gap to the pre-read ceiling is the
//! SINGLE drain thread that bridges the `!Send` `chunks()` iterator into the
//! channel — inherent to this A/B harness and to `scan_sources_fused`, not a
//! reader-pool defect. This timing floor (`>= 0.55`) is therefore a realized-
//! gain REGRESSION guard: headroom below the measured ~0.72, far above the
//! pre-fix ~0.48, so re-introducing reader oversubscription trips it while
//! healthy builds (and the drain-funnel ceiling) clear it.
//!
//! ROBUSTNESS
//! ----------
//! The assertion is a RATIO of two IN-PROCESS paths (A and B) measured on the
//! SAME machine, same corpus, same per-chunk work — so it is independent of CPU
//! clock, disk speed, and absolute timing. Each leg is best-of-4 (keep the MIN
//! wall) so scheduler noise can only shrink a measured time, never inflate the
//! ratio spuriously. The cap only manifests with real cores, so the hard
//! assertion is gated on `available_parallelism() >= 8`; on smaller hosts the
//! oversubscription is indistinguishable from the physical limit and the test
//! degrades to a recall/sanity check only.
//!
//! RECALL/CORRECTNESS GUARD
//! ------------------------
//! A and B run over the SAME set of chunks; the test asserts both observe the
//! full 4000-chunk corpus (no file silently dropped). An "optimization" that
//! made `chunks()` look faster by skipping files would change the observed
//! chunk count and fail here before the ratio is even checked.

use keyhog_core::{Chunk, Source};
use keyhog_sources::FilesystemSource;
use rayon::iter::{IntoParallelRefIterator, ParallelBridge, ParallelIterator};
use std::io::Write;
use std::time::Instant;

const FILES: usize = 4000;
const FUSED_BATCH: usize = 32;
/// Min parallel-efficiency the source pipeline must retain vs the pre-read
/// ceiling. The reader-pool OVERSUBSCRIPTION that capped this at ~0.48 is fixed
/// (a small fixed reader crew, no longer `scan_threads/2`; proven deterministic
/// in `tests/unit/filesystem.rs`), lifting realized efficiency to ~0.72. The
/// remaining gap to the ceiling is the SINGLE drain thread that bridges the
/// `!Send` `chunks()` iterator into the channel — inherent to this A/B harness
/// (and to `scan_sources_fused`), not a reader-pool defect. This floor is a
/// realized-gain REGRESSION guard at 0.55 (headroom below the measured ~0.72,
/// far above the pre-fix ~0.48): re-introducing reader oversubscription trips it.
const MIN_EFFICIENCY: f64 = 0.55;
/// The cap is only observable with enough real cores to oversubscribe.
const MIN_CORES_FOR_ASSERT: usize = 8;

fn make_tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    for i in 0..FILES {
        let sub = dir.path().join(format!("pkg{}", i / 200));
        std::fs::create_dir_all(&sub).ok();
        let mut f = std::fs::File::create(sub.join(format!("f_{i}.go"))).expect("create file");
        // ~1KB of source per file — the dominant shape of a real tree (Linux
        // kernel: ~94k files, vast majority sub-2KiB).
        let mut s = String::with_capacity(1100);
        s.push_str("package main\n");
        for j in 0..30 {
            s.push_str(&format!("func f_{i}_{j}() {{ println({j}) }}\n"));
        }
        if i % 2 == 0 {
            s.push_str(&format!("aws_access_key_id = \"AKIAIOSFODNN7{i:07}\"\n"));
        }
        f.write_all(s.as_bytes()).expect("write file");
    }
    dir
}

fn pool(n: usize) -> rayon::ThreadPool {
    rayon::ThreadPoolBuilder::new()
        .num_threads(n)
        .build()
        .expect("build rayon pool")
}

/// Representative, deterministic per-chunk CPU cost (no I/O, no allocation),
/// standing in for `scan_coalesced`'s per-chunk work so A and B do the exact
/// same compute and the ratio isolates the chunk-PRODUCTION path.
#[inline(never)]
fn per_chunk_work(c: &Chunk) -> u64 {
    let bytes = c.data.as_bytes();
    let mut acc = 0u64;
    for _ in 0..60 {
        for &b in bytes {
            acc = acc.wrapping_mul(1099511628211).wrapping_add(b as u64);
        }
    }
    acc
}

fn best_of<F: FnMut() -> (f64, usize)>(mut f: F, k: usize) -> (f64, usize) {
    let mut best = f64::INFINITY;
    let mut count = 0;
    for _ in 0..k {
        let (dt, c) = f();
        count = c;
        best = best.min(dt);
    }
    (best, count)
}

/// (B) achievable ceiling: per-chunk work over a PRE-READ owned slice.
fn ceiling(chunks: &[Chunk], threads: usize, k: usize) -> (f64, usize) {
    let p = pool(threads);
    best_of(
        || {
            let t = Instant::now();
            let s: u64 = p.install(|| {
                chunks
                    .par_iter()
                    .map(per_chunk_work)
                    .reduce(|| 0, |a, b| a.wrapping_add(b))
            });
            std::hint::black_box(s);
            (t.elapsed().as_secs_f64(), chunks.len())
        },
        k,
    )
}

/// (A) the same work driven through the live `FilesystemSource::chunks()`
/// pipeline, mirroring `dispatch.rs scan_sources_fused`: one drain thread
/// bridges the `!Send` iterator into a `sync_channel(fused_depth)`; the
/// consumer `par_bridge()`s over the channel on the current rayon pool.
fn via_source(root: &std::path::Path, threads: usize, k: usize) -> (f64, usize) {
    let p = pool(threads);
    let fused_depth = threads.saturating_add(3).saturating_div(4).clamp(2, 8);
    best_of(
        || {
            let root2 = root.to_path_buf();
            let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<Chunk>>(fused_depth);
            let t = Instant::now();
            let drain = std::thread::spawn(move || {
                let src = FilesystemSource::new(root2);
                let mut batch: Vec<Chunk> = Vec::with_capacity(FUSED_BATCH);
                for c in src.chunks() {
                    if let Ok(c) = c {
                        batch.push(c);
                        if batch.len() >= FUSED_BATCH {
                            if tx.send(std::mem::take(&mut batch)).is_err() {
                                return;
                            }
                            batch = Vec::with_capacity(FUSED_BATCH);
                        }
                    }
                }
                if !batch.is_empty() {
                    let _ = tx.send(batch);
                }
            });
            let (sum, count) = p.install(|| {
                rx.into_iter()
                    .par_bridge()
                    .map(|batch| {
                        let s = batch
                            .iter()
                            .map(per_chunk_work)
                            .fold(0u64, |a, b| a.wrapping_add(b));
                        (s, batch.len())
                    })
                    .reduce(|| (0u64, 0usize), |a, b| (a.0.wrapping_add(b.0), a.1 + b.1))
            });
            let _ = drain.join();
            std::hint::black_box(sum);
            (t.elapsed().as_secs_f64(), count)
        },
        k,
    )
}

#[test]
fn filesystem_source_multicore_scaling_floor() {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let high = cores.min(16).max(2);

    let dir = make_tree();
    let root = dir.path();

    // Pre-read the corpus once: B's input AND a page-cache warm-up so neither
    // leg pays cold-cache disk I/O (we are measuring CPU-scaling, not disk).
    let materialized: Vec<Chunk> = {
        let src = FilesystemSource::new(root.to_path_buf());
        src.chunks().collect::<Result<Vec<_>, _>>().unwrap()
    };
    assert_eq!(
        materialized.len(),
        FILES,
        "recall guard: FilesystemSource must surface every file ({} expected, {} produced) \
         before any scaling claim is meaningful",
        FILES,
        materialized.len()
    );

    const K: usize = 4;
    // Single-thread baselines.
    let (b1, _) = ceiling(&materialized, 1, K);
    let (a1, a1c) = via_source(root, 1, K);
    // High-thread.
    let (bn, bnc) = ceiling(&materialized, high, K);
    let (an, anc) = via_source(root, high, K);

    // Recall guard: both legs must see the whole corpus at every thread count.
    for (label, c) in [
        ("via_source 1t", a1c),
        ("ceiling Nt", bnc),
        ("via_source Nt", anc),
    ] {
        assert_eq!(
            c, FILES,
            "recall guard: {label} observed {c} chunks, expected {FILES} \
             (a faster-but-lossy path is not a valid optimization)"
        );
    }

    let ceil_speedup = b1 / bn; // achievable
    let src_speedup = a1 / an; // FilesystemSource pipeline
    let efficiency = if ceil_speedup > 0.0 {
        src_speedup / ceil_speedup
    } else {
        1.0
    };

    eprintln!(
        "perf_parallel_cores: cores={cores} high_threads={high} (best-of-{K})\n  \
         (B) pre-read ceiling: 1t={b1:.3}s {high}t={bn:.3}s -> {ceil_speedup:.2}x\n  \
         (A) FilesystemSource: 1t={a1:.3}s {high}t={an:.3}s -> {src_speedup:.2}x\n  \
         source efficiency = {:.0}% of ceiling (floor {:.0}%)",
        100.0 * efficiency,
        100.0 * MIN_EFFICIENCY,
    );

    if cores < MIN_CORES_FOR_ASSERT {
        eprintln!(
            "perf_parallel_cores: only {cores} cores (< {MIN_CORES_FOR_ASSERT}); \
             reader-pool oversubscription is indistinguishable from the physical \
             limit here, so the efficiency floor is not asserted on this host."
        );
        return;
    }

    assert!(
        efficiency >= MIN_EFFICIENCY,
        "FilesystemSource::chunks() multicore scaling REGRESSED: it retains only \
         {:.0}% of the achievable parallel speedup ({src_speedup:.2}x vs the \
         {ceil_speedup:.2}x the same per-chunk work reaches over a pre-read \
         slice) at {high} threads — floor is {:.0}%. The reader-pool \
         OVERSUBSCRIPTION that originally capped this (a dedicated rayon pool \
         sized clamp(scan_threads/2,2,16) running ON TOP OF the scan pool) is \
         FIXED: `reader_thread_count` is now a small fixed crew (~scan/4, capped \
         at MAX_READER_THREADS=4; proven host-independently in \
         tests/unit/filesystem.rs) that never scales with the scan pool. A value \
         this low means that oversubscription crept back — re-check \
         crates/sources/src/filesystem.rs `reader_thread_count` / the reader \
         spawn. (The residual gap to the ceiling above this floor is the SINGLE \
         drain thread bridging the `!Send` chunks() iterator into the channel — \
         inherent to this harness and to scan_sources_fused, not a reader defect.)",
        100.0 * efficiency,
        100.0 * MIN_EFFICIENCY,
    );
}
