//! Scan dispatch: producer/scanner pipeline and backend routing.
//!
//! NOTE: `--stream` previews are NOT emitted here. They are emitted from the
//! run loop (`run.rs`) against the RESOLVED `VerifiedFinding` report stream,
//! after `filter_and_resolve` / suppression / `--min-confidence`, so a streamed
//! `[stream]` line always corresponds to a reported finding (stream count ==
//! report count). Emitting on raw scanner matches here previewed findings the
//! report later dropped — a correctness/coherence bug (AUD-testing_dogfood-1).

use super::ScanOrchestrator;
use crate::orchestrator_config::autoroute_config_digest;
mod backend;
mod fused;
use anyhow::Result;
pub(crate) use backend::CachedBackendRouter;
pub(crate) use backend::backend_requires_coalesced_batch_pipeline_for_test;
use backend::{AutorouteRoutingError, MeasuredBackendRouter};
use keyhog_core::{RawMatch, Source};
use std::sync::Arc;
use std::time::Instant;

const COALESCED_BATCH_CHUNK_LIMIT: usize = 4096;
const COALESCED_PIPELINE_MAX_DEPTH: usize = 3;

#[derive(Debug, Clone, Copy)]
struct CoalescedPipelinePlan {
    batch_chunk_limit: usize,
    batch_bytes_budget: usize,
    pipeline_depth: usize,
}

fn coalesced_pipeline_plan() -> CoalescedPipelinePlan {
    let engine_cap = keyhog_scanner::megascan_input_len();
    let caps = keyhog_scanner::hw_probe::probe_hardware();
    let total_ram_bytes = caps
        .total_memory_mb
        .map(|mb| (mb as usize) * 1024 * 1024)
        .unwrap_or(0); // LAW10: empty/absent => documented numeric default, recall-safe
    // Pipeline depth is derived below from the same hardware probe. Assume the
    // max depth for the headroom clamp so worst-case resident memory remains
    // under 1/8 of system RAM even on big-VRAM cards.
    let headroom_cap = total_ram_bytes / (8 * COALESCED_PIPELINE_MAX_DEPTH);
    let batch_bytes_budget = if headroom_cap == 0 {
        engine_cap
    } else {
        engine_cap.min(headroom_cap)
    };
    let pipeline_depth = match caps.total_memory_mb {
        Some(mb) if mb >= 32 * 1024 => 3,
        Some(mb) if mb >= 16 * 1024 => 2,
        _ => 1,
    };

    CoalescedPipelinePlan {
        batch_chunk_limit: COALESCED_BATCH_CHUNK_LIMIT,
        batch_bytes_budget,
        pipeline_depth,
    }
}

impl ScanOrchestrator {
    pub(crate) fn scan_sources(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::MerkleIndex>>,
        incremental_path: Option<std::path::PathBuf>,
    ) -> Result<Vec<RawMatch>> {
        use std::sync::atomic::Ordering;

        // Fused parallel read+scan path for CPU/SIMD filesystem scans. The
        // coalesced batch pipeline below funnels the parallel reader's output
        // through one main-thread drain + one scanner thread running 23
        // sequential per-batch `par_iter`s, which pins a 32-core box at ~9
        // cores (measured: kernel scan flat from 1->32 threads). The fused
        // path scans every chunk on the global rayon pool as it streams in,
        // so reads and scans overlap continuously across all cores. GPU keeps
        // the coalesced batch pipeline (preserves gpu_parity + large-buffer
        // dispatch); see `should_use_fused_pipeline`.
        if self.should_use_fused_pipeline(&sources) {
            return self.scan_sources_fused(sources, show_progress, merkle, incremental_path);
        }

        keyhog_sources::reset_skipped_over_max_size();
        // Binary-source degradation counters live in a separate module from the
        // walker skip counters, so reset them alongside (otherwise Ghidra-fallback
        // / unreadable-binary totals leak across scans in `watch`/multi-scan runs).
        #[cfg(feature = "binary")]
        keyhog_sources::reset_binary_counters();

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
        let pipeline_plan = coalesced_pipeline_plan();
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
        let scanner = Arc::clone(&self.scanner);
        let (tx, rx) =
            std::sync::mpsc::sync_channel::<Vec<keyhog_core::Chunk>>(pipeline_plan.pipeline_depth);

        tracing::debug!(
            target: "keyhog::routing",
            pipeline_depth = pipeline_plan.pipeline_depth,
            batch_bytes_budget = pipeline_plan.batch_bytes_budget,
            batch_chunk_limit = pipeline_plan.batch_chunk_limit,
            "scan dispatch pipeline sized"
        );

        // Auto-route every batch through the persisted calibration router when
        // the user has not pinned `--backend`. Normal scans do not benchmark
        // candidates and do not apply hardware-name thresholds: every selected
        // backend must come from an installer/maintenance calibration record
        // keyed by this binary, detector digest, resolved config, host profile,
        // and workload bucket. A missing/stale/incomplete decision returns a
        // routing error before scanning instead of substituting CPU/SIMD/GPU.
        //
        // COHERENCE HAZARD: backend selection can still change the execution
        // path for the same input on different hosts, so SIMD/GPU/scalar parity
        // remains a release-blocking invariant. Benchmarks that tune detector
        // quality must pin an explicit backend; production `auto` is only as
        // trustworthy as the persisted fastest-correct calibration evidence.
        let hw_caps = keyhog_scanner::hw_probe::probe_hardware().clone();
        let pattern_count = scanner.runtime_status().pattern_count;
        let config_digest = autoroute_config_digest(&self.effective_config);
        let rules_digest = self.detector_rules_digest.clone();
        let autoroute_cache_path = Ok(self.effective_config.autoroute_cache_path.clone());
        let autoroute_gpu = self.effective_config.autoroute_gpu;
        let autoroute_calibration = self.effective_config.autoroute_calibration;
        let explicit_backend = self.effective_config.backend_override;
        let perf_trace = self.effective_config.scanner.perf_trace;

        let scanner_thread = std::thread::spawn(
            move || -> std::result::Result<Vec<RawMatch>, AutorouteRoutingError> {
                let mut findings: Vec<RawMatch> = Vec::new();
                enum BatchBackendRouter {
                    Explicit(keyhog_scanner::hw_probe::ScanBackend),
                    Measured(MeasuredBackendRouter),
                }
                let mut router = match explicit_backend {
                    Some(backend) => BatchBackendRouter::Explicit(backend),
                    None => BatchBackendRouter::Measured(MeasuredBackendRouter::new(
                        hw_caps,
                        pattern_count,
                        rules_digest,
                        config_digest,
                        autoroute_gpu,
                        autoroute_calibration,
                        autoroute_cache_path,
                        scanner.as_ref(),
                    )),
                };

                let mut prev_phase2: Option<(std::thread::JoinHandle<Vec<Vec<RawMatch>>>, usize)> =
                    None;

                let drain_prev =
                    |prev: Option<(std::thread::JoinHandle<Vec<Vec<RawMatch>>>, usize)>,
                     findings: &mut Vec<RawMatch>| {
                        if let Some((handle, scanned_count)) = prev {
                            let per_chunk = match handle.join() {
                                Ok(per_chunk) => per_chunk,
                                Err(error) => std::panic::resume_unwind(error),
                            };
                            crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                            let mut batch_findings = 0usize;
                            for chunk_findings in per_chunk {
                                batch_findings += chunk_findings.len();
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
                    let chosen_backend = match &mut router {
                        BatchBackendRouter::Explicit(backend) => *backend,
                        BatchBackendRouter::Measured(router) => {
                            router.choose(scanner.as_ref(), None, &batch)?
                        }
                    };
                    match chosen_backend {
                        // The Vyre GpuLiteralSet region-presence route is the single
                        // on-GPU trigger path. It owns backend acquisition and degrades
                        // LOUDLY to SIMD/CPU, so both an explicit GPU request and a
                        // selected Gpu/MegaScan batch land here.
                        keyhog_scanner::hw_probe::ScanBackend::Gpu
                        | keyhog_scanner::hw_probe::ScanBackend::MegaScan => {
                            drain_prev(prev_phase2.take(), &mut findings);
                            let batch_bytes: u64 = batch.iter().map(|c| c.data.len() as u64).sum();
                            tracing::debug!(
                                target: "keyhog::routing",
                                backend = "gpu",
                                batch_bytes,
                                chunks = scanned_count,
                                "batch dispatched (gpu region presence)",
                            );
                            let per_chunk = scanner.scan_chunks_with_backend(
                                &batch,
                                keyhog_scanner::hw_probe::ScanBackend::Gpu,
                            );
                            crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                            // Authoritative routing signal for the completion summary:
                            // this is the single place chunks actually run on the GPU.
                            crate::GPU_SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                            let mut batch_findings = 0usize;
                            for chunk_findings in per_chunk {
                                batch_findings += chunk_findings.len();
                                findings.extend(chunk_findings);
                            }
                            crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
                        }
                        keyhog_scanner::hw_probe::ScanBackend::CpuFallback => {
                            drain_prev(prev_phase2.take(), &mut findings);
                            let per_chunk = scanner.scan_chunks_with_backend(
                                &batch,
                                keyhog_scanner::hw_probe::ScanBackend::CpuFallback,
                            );
                            crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                            let mut batch_findings = 0usize;
                            for chunk_findings in per_chunk {
                                batch_findings += chunk_findings.len();
                                findings.extend(chunk_findings);
                            }
                            crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
                        }
                        _ => {
                            drain_prev(prev_phase2.take(), &mut findings);
                            let per_chunk = scanner.scan_coalesced(&batch);
                            crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                            let mut batch_findings = 0usize;
                            for chunk_findings in per_chunk {
                                batch_findings += chunk_findings.len();
                                findings.extend(chunk_findings);
                            }
                            crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
                        }
                    }
                    scan_dur += _scan_start.elapsed();
                    last_end = std::time::Instant::now();
                }
                drain_prev(prev_phase2.take(), &mut findings);
                if perf_trace {
                    let wall = sc_t0.elapsed().as_secs_f64().max(1e-9);
                    eprintln!(
                        "perf-trace scanner_thread: wall={:.2}s scan={:.2}s recv_wait={:.2}s (scan {:.0}%, recv_wait {:.0}%)",
                        wall,
                        scan_dur.as_secs_f64(),
                        recv_dur.as_secs_f64(),
                        100.0 * scan_dur.as_secs_f64() / wall,
                        100.0 * recv_dur.as_secs_f64() / wall,
                    );
                }
                // Scanner owns the profiling switch and all report shards; the
                // CLI only asks the compiled scanner to drain them at scan end.
                scanner.dump_profile_reports("keyhog scan");
                Ok(findings)
            },
        );

        let mut batch: Vec<keyhog_core::Chunk> =
            Vec::with_capacity(pipeline_plan.batch_chunk_limit);
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
            // Per-source outcome: a source that yields ZERO chunks AND errors
            // failed entirely (e.g. --github-org with a bad token), even if a
            // co-requested source succeeded. Tracked so `run()` can fail closed
            // rather than report "clean" off another source's data.
            let mut src_chunks = 0usize;
            let mut src_errored = false;
            for chunk_result in source.chunks() {
                match chunk_result {
                    Ok(c) if c.data.len() <= 512 * 1024 * 1024 => {
                        src_chunks += 1;
                        if let (Some(idx), Some(path_str)) =
                            (merkle.as_ref(), c.metadata.path.as_deref())
                        {
                            let path = std::path::PathBuf::from(path_str);
                            if idx.record_chunk_at_offset_and_check_unchanged(
                                path,
                                c.metadata.base_offset as u64,
                                c.metadata.mtime_ns.unwrap_or(0), // LAW10: empty/absent => documented numeric default, recall-safe
                                c.metadata.size_bytes.unwrap_or(0), // LAW10: empty/absent => documented numeric default, recall-safe
                                c.data.as_bytes(),
                            ) {
                                skipped_unchanged += 1;
                                continue;
                            }
                        }

                        let len = c.data.len();
                        batch.push(c);
                        batch_bytes += len;
                        crate::TOTAL_CHUNKS.fetch_add(1, Ordering::Relaxed);
                        if batch.len() >= pipeline_plan.batch_chunk_limit
                            || batch_bytes >= pipeline_plan.batch_bytes_budget
                        {
                            send_batch(&mut batch, &mut batch_bytes, &mut pipeline_alive);
                            if !pipeline_alive {
                                break 'sources;
                            }
                        }
                    }
                    Ok(c) => {
                        src_chunks += 1;
                        let mb = c.data.len() / (1024 * 1024);
                        let path = c.metadata.path.as_deref().unwrap_or("<unknown>"); // LAW10: absent path/field => display placeholder for REPORTING only; finding still emitted, recall-safe
                        tracing::warn!(
                            path = %path,
                            size_mb = mb,
                            "skipping chunk over 512 MiB scan ceiling"
                        );
                    }
                    Err(e) => {
                        let _receipt = crate::record_source_error();
                        src_errored = true;
                        tracing::warn!("source: {e}");
                    }
                }
            }
            if src_chunks == 0 && src_errored {
                let _receipt = crate::record_failed_source();
            }
        }

        send_batch(&mut batch, &mut batch_bytes, &mut pipeline_alive);
        drop(tx);
        let findings = match scanner_thread.join() {
            Ok(Ok(findings)) => findings,
            Ok(Err(error)) => {
                progress_done.store(true, std::sync::atomic::Ordering::Relaxed);
                if let Some(h) = progress_handle {
                    let _ = h.join(); // LAW10: unused-binding marker; no runtime effect, not a fallback
                }
                return Err(error.into());
            }
            Err(error) => {
                drop(error);
                tracing::error!("scanner thread panicked mid-scan; results are incomplete");
                let _receipt = crate::record_scanner_panic();
                Vec::new()
            }
        };

        progress_done.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(h) = progress_handle {
            let _ = h.join(); // LAW10: unused-binding marker; no runtime effect, not a fallback
        }

        self.finalize_incremental(
            merkle.as_ref(),
            incremental_path.as_deref(),
            skipped_unchanged,
            &findings,
        );

        Ok(findings)
    }

    /// Persist the merkle index after a scan and log skip stats. Shared by
    /// the coalesced batch pipeline and the fused parallel path so both honour
    /// the same incremental-mode safety contract.
    fn finalize_incremental(
        &self,
        merkle: Option<&Arc<keyhog_core::MerkleIndex>>,
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
            if let Err(e) = idx.save_with_spec(path, &self.detector_spec_hash) {
                tracing::warn!(error = %e, "failed to persist merkle index");
                eprintln!(
                    "warning: incremental cache {} could not be persisted: {e}; \
                     this scan completed, but unchanged files will be re-scanned \
                     until the cache path is fixed",
                    path.display()
                );
                let _receipt = crate::record_incremental_cache_persist_failed();
            }
        }
    }
}
