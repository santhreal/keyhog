//! Scan dispatch: producer/scanner pipeline and backend routing.

use super::reporting::stream_finding_preview;
use super::ScanOrchestrator;
use keyhog_core::{RawMatch, Source};
use std::sync::Arc;
use std::time::Instant;

/// Returns the backend the user explicitly forced via `KEYHOG_BACKEND`
/// or `--backend <name>`.
///
/// Thin re-export over `keyhog_scanner::hw_probe::forced_backend_from_env`
/// so the orchestrator and the scanner agree on the parsed override
/// set (including aliases like `literal-set` and `regex-nfa`). The
/// previous hand-rolled match here drifted from the scanner-side
/// match table; consolidating means new aliases only need to land in
/// one place.
pub fn explicit_backend_override() -> Option<keyhog_scanner::hw_probe::ScanBackend> {
    // Use the uncached parser. This is called once per scan startup, not
    // per-file, so the per-file cache that `forced_backend_from_env` shares
    // with `select_backend` is unnecessary here - and using it would have a
    // subtle side effect: integration tests that flip `KEYHOG_BACKEND`
    // between cases in a single test binary would all observe the first
    // value the cache locked in.
    keyhog_scanner::hw_probe::forced_backend_from_env_uncached()
}

impl ScanOrchestrator {
    pub(crate) fn scan_sources(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::merkle_index::MerkleIndex>>,
    ) -> Vec<RawMatch> {
        use std::sync::atomic::Ordering;

        // Fused parallel read+scan path for CPU/SIMD filesystem scans. The
        // legacy batch pipeline below funnels the parallel reader's output
        // through one main-thread drain + one scanner thread running 23
        // sequential per-batch `par_iter`s, which pins a 32-core box at ~9
        // cores (measured: kernel scan flat from 1->32 threads). The fused
        // path scans every chunk on the global rayon pool as it streams in,
        // so reads and scans overlap continuously across all cores. GPU keeps
        // the coalesced batch pipeline (preserves gpu_parity + large-buffer
        // dispatch); see `should_use_fused_pipeline`.
        if self.should_use_fused_pipeline(&sources) {
            return self.scan_sources_fused(sources, show_progress, merkle);
        }

        keyhog_sources::reset_skipped_over_max_size();

        let progress_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let progress_handle = if show_progress && !self.args.stream {
            let done = Arc::clone(&progress_done);
            let started_t = Instant::now();
            Some(std::thread::spawn(move || {
                super::reporting::progress_ticker(done, started_t)
            }))
        } else {
            None
        };

        let incremental_path = self.incremental_cache_path();

        const BATCH_CHUNK_LIMIT: usize = 4096;
        // Bytes budget per coalesced batch. Sized to match the
        // engine's `megascan_input_len()` (the pre-compiled
        // `RulePipeline` input cap) so the GPU dispatch never
        // auto-degrades to literal-set on oversized batches and we
        // capture every regex-NFA win. The engine sizes its cap by
        // VRAM (1 GiB on RTX 4090/5090, 256 MiB default), so the
        // orchestrator inherits that scaling automatically.
        //
        // Clamped so worst-case resident memory (`pipeline_depth ×
        // batch_bytes_budget`) stays under 1/8 of system RAM. On a
        // 16 GiB CI runner with a hypothetical 24+ GiB-VRAM card,
        // the engine's 1 GiB cap × depth 3 would otherwise float
        // toward 3 GiB resident which earlyoom flags before the
        // scanner gets useful work done. Safer to cap the batch
        // (still well over the dispatch breakeven for any card big
        // enough to want the bigger buffer) than to break the
        // memory-safety invariant.
        let batch_bytes_budget: usize = {
            let engine_cap = keyhog_scanner::engine::megascan_input_len();
            let total_ram_bytes = keyhog_scanner::hw_probe::probe_hardware()
                .total_memory_mb
                .map(|mb| (mb as usize) * 1024 * 1024)
                .unwrap_or(0);
            // Pipeline depth here is still being computed below, so
            // assume the max (3) for the headroom clamp. Worst case
            // is the orchestrator picking depth=1 and only using a
            // third of the headroom - safe in the under-direction.
            let headroom_cap = total_ram_bytes / (8 * 3);
            if headroom_cap == 0 {
                engine_cap
            } else {
                engine_cap.min(headroom_cap)
            }
        };
        // Producer/scanner pipeline depth. Each in-flight batch holds up
        // to `batch_bytes_budget` (256 MiB default, up to 1 GiB on
        // big-VRAM cards) of coalesced chunks, so the worst-case
        // resident memory floor is depth * batch_bytes_budget. Higher
        // depth lets the reader prefetch the next batch while the
        // scanner is still grinding the previous one - critical at
        // multi-TB scale where IO and GPU dispatch take similar wall-
        // clock time and depth=1 leaves whichever finishes first
        // idling. The previous fixed depth=1 fully serialized the two
        // sides; on a 96 GB workstation reading 5 TB of source, that
        // costs roughly half of total throughput.
        //
        // Adaptive by total system memory:
        //   - >= 32 GiB: depth 3 (~3x readahead).
        //   - >= 16 GiB: depth 2.
        //   -  < 16 GiB: depth 1 (the safe original behavior, since
        //                 jumping to a multi-batch peak on a small host
        //                 risks earlyoom).
        //
        // The peak resident is now `depth × batch_bytes_budget`, where
        // batch_bytes_budget is itself capped at RAM/24 above, so even
        // depth=3 cannot push us past 1/8 of system RAM.
        let pipeline_depth: usize = {
            let caps = keyhog_scanner::hw_probe::probe_hardware();
            match caps.total_memory_mb {
                Some(mb) if mb >= 32 * 1024 => 3,
                Some(mb) if mb >= 16 * 1024 => 2,
                _ => 1,
            }
        };

        let scanner = Arc::clone(&self.scanner);
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<keyhog_core::Chunk>>(pipeline_depth);

        tracing::debug!(
            target: "keyhog::routing",
            pipeline_depth,
            batch_bytes_budget,
            batch_chunk_limit = BATCH_CHUNK_LIMIT,
            "scan dispatch pipeline sized"
        );

        let stream = self.args.stream;
        // Auto-route every batch through `select_backend` when the user has not
        // pinned KEYHOG_BACKEND. Previously the default (no-override) path fell
        // straight into the SIMD `scan_coalesced` arm, so on a discrete-GPU host
        // the GPU engine and its phase1/phase2 streaming overlap were dead
        // unless `KEYHOG_BACKEND=gpu` was set explicitly - the documented
        // GPU-default behaviour had regressed to opt-in. `select_backend`
        // already gates GPU on availability + tier thresholds and returns SIMD
        // under `env_no_gpu()` (CI), so this is a no-op on CI and on small
        // batches, and the GPU init path degrades to SIMD if the device is
        // unusable. Captured once and moved into the scanner thread.
        //
        // COHERENCE HAZARD: because this auto-routes by hardware + batch
        // size, the DEFAULT scan result is a function of which machine ran
        // it and how files were batched (a >= GPU_MIN_BYTES_HIGH_TIER batch
        // on a discrete-GPU host takes the GPU phase1/phase2 path; a smaller
        // batch or a CI host takes SIMD `scan_coalesced`). SIMD and GPU MUST
        // produce identical findings for this to be safe. That equivalence
        // is not self-evident (see `crates/scanner/tests/diagnose_sb_divergence.rs`
        // and the `gpu_parity` gate), so two invariants live OUTSIDE this
        // file and must hold for tuned == benched == shipped:
        //   1. Benchmarks pin a deterministic backend (score.py sets
        //      KEYHOG_BACKEND=simd / KEYHOG_NO_GPU=1) so the tuned F1 is not
        //      silently measured on a different code path than what ships.
        //   2. GPU-vs-SIMD parity is a RELEASE BLOCKER (gpu_parity), so
        //      auto-routing can never change the finding set under the user.
        // Do not relax either without re-checking this site.
        let hw_caps = keyhog_scanner::hw_probe::probe_hardware();
        let pattern_count = scanner.pattern_count();

        let scanner_thread = std::thread::spawn(move || {
            let mut findings: Vec<RawMatch> = Vec::new();
            let mut stderr_writer = if stream {
                Some(std::io::LineWriter::new(std::io::stderr()))
            } else {
                None
            };

            let mut prev_phase2: Option<(std::thread::JoinHandle<Vec<Vec<RawMatch>>>, usize)> =
                None;

            let drain_prev =
                |prev: Option<(std::thread::JoinHandle<Vec<Vec<RawMatch>>>, usize)>,
                 findings: &mut Vec<RawMatch>,
                 stderr_writer: &mut Option<std::io::LineWriter<std::io::Stderr>>| {
                    if let Some((handle, scanned_count)) = prev {
                        let per_chunk = handle.join().unwrap_or_else(|e| {
                            std::panic::resume_unwind(e);
                        });
                        crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                        let mut batch_findings = 0usize;
                        for chunk_findings in per_chunk {
                            batch_findings += chunk_findings.len();
                            if let Some(w) = stderr_writer.as_mut() {
                                for m in &chunk_findings {
                                    stream_finding_preview(w, m);
                                }
                            }
                            findings.extend(chunk_findings);
                        }
                        crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
                    }
                };

            let sc_t0 = std::time::Instant::now();
            let mut scan_dur = std::time::Duration::ZERO;
            let mut recv_dur = std::time::Duration::ZERO;
            let mut last_end = std::time::Instant::now();
            for batch in rx {
                recv_dur += last_end.elapsed();
                if batch.is_empty() {
                    last_end = std::time::Instant::now();
                    continue;
                }
                let _scan_start = std::time::Instant::now();
                let scanned_count = batch.len();
                // Explicit KEYHOG_BACKEND wins; otherwise auto-route this batch
                // by size/pattern-count/hardware. Auto-routed Gpu/MegaScan land
                // in the same streaming arms as the explicit choice below.
                let chosen_backend = explicit_backend_override().or_else(|| {
                    let batch_bytes: u64 = batch.iter().map(|c| c.data.len() as u64).sum();
                    // Large-chunk DOMINANCE drives the GPU/SIMD decision: the
                    // device cost is paid on the whole coalesced buffer, so GPU
                    // pays off only when most of the batch is genuinely large-
                    // file data it can accelerate. A swarm of tiny files (the
                    // kernel tree: 94k files, only 55 >= 2 MiB, sprinkled
                    // through the walk) never clears the dominance bar no matter
                    // how the large files cluster, so it stays on SIMD - measured
                    // 2.1x faster + 3x less RSS than routing the coalesced total
                    // to the GPU. `large_chunk_bytes` sums only chunks at/above
                    // the tier's per-file GPU floor. See `select_backend_for_batch`.
                    let tier =
                        keyhog_scanner::hw_probe::classify_gpu_tier(hw_caps.gpu_name.as_deref());
                    let gpu_floor = keyhog_scanner::hw_probe::gpu_min_bytes_for_tier(tier);
                    let large_chunk_bytes: u64 = batch
                        .iter()
                        .map(|c| c.data.len() as u64)
                        .filter(|&n| n >= gpu_floor)
                        .sum();
                    Some(keyhog_scanner::hw_probe::select_backend_for_batch(
                        &hw_caps,
                        batch_bytes,
                        pattern_count,
                        large_chunk_bytes,
                    ))
                });
                match chosen_backend {
                    Some(keyhog_scanner::hw_probe::ScanBackend::Gpu) => {
                        let batch_bytes: u64 = batch.iter().map(|c| c.data.len() as u64).sum();
                        tracing::debug!(
                            target: "keyhog::routing",
                            backend = "gpu",
                            batch_bytes,
                            chunks = scanned_count,
                            "batch dispatched (gpu, pipelined)",
                        );
                        match scanner.scan_coalesced_gpu_phase1(&batch) {
                            keyhog_scanner::GpuPhase1Output::Done(per_chunk) => {
                                drain_prev(prev_phase2.take(), &mut findings, &mut stderr_writer);
                                crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                                let mut batch_findings = 0usize;
                                for chunk_findings in per_chunk {
                                    batch_findings += chunk_findings.len();
                                    if let Some(w) = stderr_writer.as_mut() {
                                        for m in &chunk_findings {
                                            stream_finding_preview(w, m);
                                        }
                                    }
                                    findings.extend(chunk_findings);
                                }
                                crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
                            }
                            keyhog_scanner::GpuPhase1Output::Hits(per_chunk_hits) => {
                                drain_prev(prev_phase2.take(), &mut findings, &mut stderr_writer);
                                let scanner_clone = Arc::clone(&scanner);
                                let batch_owned = batch;
                                let handle = std::thread::spawn(move || {
                                    scanner_clone
                                        .scan_coalesced_gpu_phase2(&batch_owned, per_chunk_hits)
                                });
                                prev_phase2 = Some((handle, scanned_count));
                            }
                        }
                    }
                    Some(backend @ keyhog_scanner::hw_probe::ScanBackend::MegaScan) => {
                        drain_prev(prev_phase2.take(), &mut findings, &mut stderr_writer);
                        let batch_bytes: u64 = batch.iter().map(|c| c.data.len() as u64).sum();
                        tracing::debug!(
                            target: "keyhog::routing",
                            backend = backend.label(),
                            batch_bytes,
                            chunks = scanned_count,
                            "batch dispatched (megascan, sync)",
                        );
                        let per_chunk = scanner.scan_chunks_with_backend(&batch, backend);
                        crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                        let mut batch_findings = 0usize;
                        for chunk_findings in per_chunk {
                            batch_findings += chunk_findings.len();
                            if let Some(w) = stderr_writer.as_mut() {
                                for m in &chunk_findings {
                                    stream_finding_preview(w, m);
                                }
                            }
                            findings.extend(chunk_findings);
                        }
                        crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
                    }
                    _ => {
                        drain_prev(prev_phase2.take(), &mut findings, &mut stderr_writer);
                        let per_chunk = scanner.scan_coalesced(&batch);
                        crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                        let mut batch_findings = 0usize;
                        for chunk_findings in per_chunk {
                            batch_findings += chunk_findings.len();
                            if let Some(w) = stderr_writer.as_mut() {
                                for m in &chunk_findings {
                                    stream_finding_preview(w, m);
                                }
                            }
                            findings.extend(chunk_findings);
                        }
                        crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
                    }
                }
                scan_dur += _scan_start.elapsed();
                last_end = std::time::Instant::now();
            }
            drain_prev(prev_phase2.take(), &mut findings, &mut stderr_writer);
            if std::env::var("KH_PERF").is_ok() {
                let wall = sc_t0.elapsed().as_secs_f64().max(1e-9);
                eprintln!(
                    "KH_PERF scanner_thread: wall={:.2}s scan={:.2}s recv_wait={:.2}s (scan {:.0}%, recv_wait {:.0}%)",
                    wall, scan_dur.as_secs_f64(), recv_dur.as_secs_f64(),
                    100.0 * scan_dur.as_secs_f64() / wall,
                    100.0 * recv_dur.as_secs_f64() / wall,
                );
            }
            findings
        });

        let mut batch: Vec<keyhog_core::Chunk> = Vec::with_capacity(BATCH_CHUNK_LIMIT);
        let mut batch_bytes: usize = 0;
        let mut skipped_unchanged = 0usize;
        let mut pipeline_alive = true;

        let send_batch =
            |batch: &mut Vec<keyhog_core::Chunk>, batch_bytes: &mut usize, alive: &mut bool| {
                if !*alive || batch.is_empty() {
                    batch.clear();
                    *batch_bytes = 0;
                    return;
                }
                let payload = std::mem::take(batch);
                *batch_bytes = 0;
                if tx.send(payload).is_err() {
                    *alive = false;
                }
            };

        'sources: for source in &sources {
            for chunk_result in source.chunks() {
                match chunk_result {
                    Ok(c) if c.data.len() <= 512 * 1024 * 1024 => {
                        if let (Some(idx), Some(path_str)) =
                            (merkle.as_ref(), c.metadata.path.as_deref())
                        {
                            let chunk_hash = keyhog_core::merkle_index::MerkleIndex::hash_content(
                                c.data.as_bytes(),
                            );
                            let path = std::path::PathBuf::from(path_str);
                            if idx.unchanged(&path, &chunk_hash) {
                                idx.record_with_metadata(
                                    path,
                                    c.metadata.mtime_ns.unwrap_or(0),
                                    c.metadata.size_bytes.unwrap_or(0),
                                    chunk_hash,
                                );
                                skipped_unchanged += 1;
                                continue;
                            }
                            idx.record_with_metadata(
                                path,
                                c.metadata.mtime_ns.unwrap_or(0),
                                c.metadata.size_bytes.unwrap_or(0),
                                chunk_hash,
                            );
                        }

                        let len = c.data.len();
                        batch.push(c);
                        batch_bytes += len;
                        crate::TOTAL_CHUNKS.fetch_add(1, Ordering::Relaxed);
                        if batch.len() >= BATCH_CHUNK_LIMIT || batch_bytes >= batch_bytes_budget {
                            send_batch(&mut batch, &mut batch_bytes, &mut pipeline_alive);
                            if !pipeline_alive {
                                break 'sources;
                            }
                        }
                    }
                    Ok(c) => {
                        let mb = c.data.len() / (1024 * 1024);
                        let path = c.metadata.path.as_deref().unwrap_or("<unknown>");
                        tracing::warn!(
                            path = %path,
                            size_mb = mb,
                            "skipping chunk over 512 MiB scan ceiling"
                        );
                    }
                    Err(e) => tracing::warn!("source: {e}"),
                }
            }
        }

        send_batch(&mut batch, &mut batch_bytes, &mut pipeline_alive);
        drop(tx);
        let findings = scanner_thread.join().unwrap_or_else(|_| {
            tracing::error!("scanner thread panicked mid-scan; results are incomplete");
            crate::SCANNER_PANICKED.store(true, std::sync::atomic::Ordering::Relaxed);
            Vec::new()
        });

        progress_done.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = progress_handle {
            let _ = h.join();
        }

        self.finalize_incremental(
            merkle.as_ref(),
            incremental_path.as_deref(),
            skipped_unchanged,
            &findings,
        );

        findings
    }

    /// Persist the merkle index after a scan and log skip stats. Shared by
    /// the legacy batch pipeline and the fused parallel path so both honour
    /// the same incremental-mode safety contract.
    fn finalize_incremental(
        &self,
        merkle: Option<&Arc<keyhog_core::merkle_index::MerkleIndex>>,
        incremental_path: Option<&std::path::Path>,
        skipped_unchanged: usize,
        findings: &[RawMatch],
    ) {
        if skipped_unchanged > 0 {
            tracing::info!(
                skipped = skipped_unchanged,
                "incremental scan: skipped unchanged files"
            );
        }
        if let (Some(idx), Some(path)) = (merkle, incremental_path) {
            // Incremental-mode safety: never persist a file that produced a
            // finding. Otherwise an unchanged secret-bearing file would be
            // skipped on the next run and the secret would silently vanish from
            // the report (exit 0) - the exact "missed detection forever" this
            // index must not cause. Dropping the entry forces a re-scan + re-
            // report next time; clean files stay cached so the speedup holds.
            for m in findings {
                if let Some(fp) = m.location.file_path.as_deref() {
                    idx.forget(std::path::Path::new(fp));
                }
            }
            let spec_hash = keyhog_core::merkle_index::compute_spec_hash(&self.detectors);
            if let Err(e) = idx.save_with_spec(path, &spec_hash) {
                tracing::warn!(error = %e, "failed to persist merkle index");
            }
        }
    }

    /// Decide whether a scan runs on the fused parallel read+scan path.
    ///
    /// Engaged only for the CPU/SIMD backend on filesystem sources:
    /// * **GPU** (forced, or auto-selected on a real GPU host) keeps the
    ///   coalesced per-batch pipeline so `gpu_parity` and the large-buffer
    ///   dispatch are untouched.
    /// * **Non-filesystem sources** (git, stdin, docker, ...) may emit
    ///   *gapless* chunks where `scan_chunk_boundaries` is load-bearing; the
    ///   fused path scans each chunk independently and relies on the
    ///   filesystem source's 128 KiB window *overlap* (for which the boundary
    ///   pass is already a no-op) to cover seam-straddling secrets.
    /// * `KEYHOG_LEGACY_PIPELINE=1` forces the batch path (A/B + escape hatch).
    fn should_use_fused_pipeline(&self, sources: &[Box<dyn Source>]) -> bool {
        if std::env::var_os("KEYHOG_LEGACY_PIPELINE").is_some() {
            return false;
        }
        let explicit = explicit_backend_override();
        let hw = keyhog_scanner::hw_probe::probe_hardware();
        let gpu_in_play = match explicit {
            Some(keyhog_scanner::hw_probe::ScanBackend::Gpu)
            | Some(keyhog_scanner::hw_probe::ScanBackend::MegaScan) => true,
            Some(keyhog_scanner::hw_probe::ScanBackend::SimdCpu)
            | Some(keyhog_scanner::hw_probe::ScanBackend::CpuFallback) => false,
            // `ScanBackend` is #[non_exhaustive]: an unknown future backend
            // stays on the legacy pipeline (it auto-routes/handles any
            // backend), rather than silently forcing the CPU fused path.
            Some(_) => true,
            None => hw.gpu_available && !hw.gpu_is_software && !keyhog_scanner::gpu::env_no_gpu(),
        };
        if gpu_in_play {
            return false;
        }
        !sources.is_empty()
            && sources
                .iter()
                .all(|s| s.as_any().is::<keyhog_sources::FilesystemSource>())
    }

    /// Fused parallel read+scan: stream chunks off the source's parallel
    /// reader pool and scan each on the global rayon pool via `par_bridge`,
    /// so I/O and CPU overlap continuously across all cores with no
    /// single-thread drain and no per-batch barrier.
    ///
    /// A small drain thread bridges the source's non-`Send` chunk iterator
    /// into a bounded `Send` channel that the global pool consumes; the
    /// reader pool (dedicated, inside the source) and the global scan pool
    /// are distinct, so neither starves the other (the deadlock the legacy
    /// pipeline's dedicated reader pool was built to avoid).
    fn scan_sources_fused(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::merkle_index::MerkleIndex>>,
    ) -> Vec<RawMatch> {
        use rayon::iter::{ParallelBridge, ParallelIterator};
        use std::sync::atomic::{AtomicUsize, Ordering};

        keyhog_sources::reset_skipped_over_max_size();

        let progress_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let progress_handle = if show_progress && !self.args.stream {
            let done = Arc::clone(&progress_done);
            let started_t = Instant::now();
            Some(std::thread::spawn(move || {
                super::reporting::progress_ticker(done, started_t)
            }))
        } else {
            None
        };

        let incremental_path = self.incremental_cache_path();
        let scanner = Arc::clone(&self.scanner);
        let stream = self.args.stream;

        let skipped_unchanged = Arc::new(AtomicUsize::new(0));
        let sc_t0 = Instant::now();

        // Bridge the source's `!Send` chunk iterator into a `Send` channel of
        // BATCHES that the global pool consumes via `par_bridge`. Reusing
        // `scan_coalesced` per batch keeps the finding set bit-identical to the
        // legacy pipeline (same scan entry, same phase-1 HS prefilter + no-hit
        // gating); parallelising ACROSS batches is what removes the legacy
        // single scanner-thread funnel that pinned a 32-core box at ~9 cores.
        // `scan_coalesced` already calls the HS prefilter concurrently from its
        // own internal `par_iter`, so invoking it from several batch workers at
        // once is the same proven concurrency model, just wider. Batches are
        // small enough that the outer `par_bridge` keeps every core busy and
        // large enough to amortise scan_coalesced's per-batch phase/collect
        // cost. The drain thread only groups chunks + enforces the 512 MiB
        // ceiling; merkle hashing + scanning run in parallel in the consumer.
        //
        // Measured flat optimum on small-file filesystem corpora: finer
        // batches keep the outer parallel bridge balanced while bounding
        // in-flight chunk memory; deeper buffering lets the drain thread stay
        // ahead without exposing operator-facing knobs.
        const FUSED_BATCH: usize = 16;
        const FUSED_DEPTH: usize = 256;
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<keyhog_core::Chunk>>(FUSED_DEPTH);
        let drain = std::thread::spawn(move || {
            let mut batch: Vec<keyhog_core::Chunk> = Vec::with_capacity(FUSED_BATCH);
            'sources: for source in &sources {
                for chunk_result in source.chunks() {
                    match chunk_result {
                        Ok(c) if c.data.len() <= 512 * 1024 * 1024 => {
                            batch.push(c);
                            if batch.len() >= FUSED_BATCH {
                                if tx.send(std::mem::take(&mut batch)).is_err() {
                                    break 'sources;
                                }
                                batch = Vec::with_capacity(FUSED_BATCH);
                            }
                        }
                        Ok(c) => {
                            let mb = c.data.len() / (1024 * 1024);
                            let path = c.metadata.path.as_deref().unwrap_or("<unknown>");
                            tracing::warn!(
                                path = %path,
                                size_mb = mb,
                                "skipping chunk over 512 MiB scan ceiling"
                            );
                        }
                        Err(e) => tracing::warn!("source: {e}"),
                    }
                }
            }
            if !batch.is_empty() {
                let _ = tx.send(batch);
            }
        });

        let stream_writer = if stream {
            Some(std::sync::Mutex::new(std::io::LineWriter::new(
                std::io::stderr(),
            )))
        } else {
            None
        };

        let merkle_ref = merkle.as_ref();
        let skipped_ref = &skipped_unchanged;
        let stream_ref = stream_writer.as_ref();
        let scanner_ref = scanner.as_ref();

        let findings: Vec<RawMatch> = rx
            .into_iter()
            .par_bridge()
            .flat_map_iter(|batch| {
                // Incremental skip (parallel across batches): hash each chunk
                // and drop the ones the merkle index already has unchanged.
                // Mirrors the legacy producer: record metadata for every chunk
                // seen (changed or not); `finalize_incremental` later forgets
                // any path that produced a finding.
                let batch: Vec<keyhog_core::Chunk> = if let Some(idx) = merkle_ref {
                    batch
                        .into_iter()
                        .filter(|c| {
                            let Some(path_str) = c.metadata.path.as_deref() else {
                                return true;
                            };
                            let chunk_hash = keyhog_core::merkle_index::MerkleIndex::hash_content(
                                c.data.as_bytes(),
                            );
                            let path = std::path::PathBuf::from(path_str);
                            let unchanged = idx.unchanged(&path, &chunk_hash);
                            idx.record_with_metadata(
                                path,
                                c.metadata.mtime_ns.unwrap_or(0),
                                c.metadata.size_bytes.unwrap_or(0),
                                chunk_hash,
                            );
                            if unchanged {
                                skipped_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            !unchanged
                        })
                        .collect()
                } else {
                    batch
                };
                if batch.is_empty() {
                    return Vec::new();
                }

                crate::TOTAL_CHUNKS.fetch_add(batch.len(), Ordering::Relaxed);
                let per_chunk = scanner_ref.scan_coalesced(&batch);
                crate::SCANNED_CHUNKS.fetch_add(batch.len(), Ordering::Relaxed);

                let mut out: Vec<RawMatch> = Vec::new();
                let mut batch_findings = 0usize;
                for chunk_findings in per_chunk {
                    batch_findings += chunk_findings.len();
                    if let Some(w) = stream_ref {
                        if let Ok(mut w) = w.lock() {
                            for m in &chunk_findings {
                                stream_finding_preview(&mut *w, m);
                            }
                        }
                    }
                    out.extend(chunk_findings);
                }
                if batch_findings > 0 {
                    crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
                }
                out
            })
            .collect();

        // Drain thread only moves chunks; it finishes once the source is
        // exhausted and the channel is consumed.
        let _ = drain.join();

        if std::env::var("KH_PERF").is_ok() {
            eprintln!(
                "KH_PERF scan_sources_fused: wall={:.2}s findings={} scanned={}",
                sc_t0.elapsed().as_secs_f64(),
                findings.len(),
                crate::SCANNED_CHUNKS.load(Ordering::Relaxed),
            );
        }

        progress_done.store(true, Ordering::Relaxed);
        if let Some(h) = progress_handle {
            let _ = h.join();
        }

        let skipped_unchanged = skipped_unchanged.load(Ordering::Relaxed);
        self.finalize_incremental(
            merkle.as_ref(),
            incremental_path.as_deref(),
            skipped_unchanged,
            &findings,
        );

        findings
    }
}
