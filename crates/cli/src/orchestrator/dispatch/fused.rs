//! Fused filesystem read+scan dispatch path.

use super::backend::{
    backend_requires_coalesced_batch_pipeline, explicit_backend_override, CachedBackendRouter,
    MeasuredBackendRouter,
};
use crate::orchestrator::ScanOrchestrator;
use crate::orchestrator_config::autoroute_config_digest;
use anyhow::Result;
use keyhog_core::{RawMatch, Source};
use std::sync::{Arc, Mutex};
use std::time::Instant;

enum ActiveBackendRouter {
    Explicit(keyhog_scanner::hw_probe::ScanBackend),
    Cached(CachedBackendRouter),
    Measured(Arc<Mutex<MeasuredBackendRouter>>),
}

impl ScanOrchestrator {
    /// Decide whether a scan runs on the fused parallel read+scan path.
    ///
    /// Engaged for filesystem sources unless the operator explicitly forced a
    /// GPU backend:
    /// * **GPU/MegaScan forced by the user** keeps the coalesced per-batch
    ///   pipeline so `gpu_parity` and the large-buffer dispatch are untouched.
    ///   Default/auto filesystem scans stay fused. Persisted autoroute
    ///   decisions are consumed per fused batch, where the exact workload key is
    ///   known, so a GPU decision for one bucket cannot disable fused
    ///   filesystem scanning globally.
    /// * **Non-filesystem sources** (git, stdin, docker, ...) may emit
    ///   *gapless* chunks where `scan_chunk_boundaries` is load-bearing; the
    ///   fused path scans each chunk independently and relies on the
    ///   filesystem source's 128 KiB window *overlap* (for which the boundary
    ///   pass is already a no-op) to cover seam-straddling secrets.
    /// * `KEYHOG_BATCH_PIPELINE=1` forces the coalesced batch path (A/B + escape hatch).
    pub(super) fn should_use_fused_pipeline(&self, sources: &[Box<dyn Source>]) -> bool {
        if std::env::var_os("KEYHOG_BATCH_PIPELINE").is_some() {
            return false;
        }
        let explicit = explicit_backend_override();
        // Explicit GPU runs on the coalesced batch pipeline for diagnostics and
        // large-buffer parity. Auto GPU is a per-batch autoroute decision inside
        // the fused path, never a global switch based on another bucket.
        if backend_requires_coalesced_batch_pipeline(explicit) {
            return false;
        }
        !sources.is_empty()
            && sources
                .iter()
                .all(|s| s.as_any().is::<keyhog_sources::FilesystemSource>())
    }

    fn cached_backend_router(&self) -> CachedBackendRouter {
        let (hw_caps, pattern_count, rules_digest, config_digest) = self.autoroute_router_inputs();
        CachedBackendRouter::new(
            hw_caps,
            pattern_count,
            rules_digest,
            config_digest,
            self.scanner.as_ref(),
        )
    }

    fn measured_backend_router(&self) -> MeasuredBackendRouter {
        let (hw_caps, pattern_count, rules_digest, config_digest) = self.autoroute_router_inputs();
        MeasuredBackendRouter::new(
            hw_caps,
            pattern_count,
            rules_digest,
            config_digest,
            self.scanner.as_ref(),
        )
    }

    fn autoroute_router_inputs(
        &self,
    ) -> (keyhog_scanner::hw_probe::HardwareCaps, usize, String, u64) {
        let hw_caps = keyhog_scanner::hw_probe::probe_hardware().clone();
        let pattern_count = self.scanner.runtime_status().pattern_count;
        let config_digest = autoroute_config_digest(&self.effective_config);
        let rules_digest =
            keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(&self.detectors));
        (hw_caps, pattern_count, rules_digest, config_digest)
    }

    /// Fused parallel read+scan: stream chunks off the source's parallel
    /// reader pool and scan each on the global rayon pool via `par_bridge`,
    /// so I/O and CPU overlap continuously across all cores with no
    /// single-thread drain and no per-batch barrier.
    ///
    /// A small drain thread bridges the source's non-`Send` chunk iterator
    /// into a bounded `Send` channel that the global pool consumes; the
    /// reader pool (dedicated, inside the source) and the global scan pool
    /// are distinct, so neither starves the other.
    pub(super) fn scan_sources_fused(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::merkle_index::MerkleIndex>>,
    ) -> Result<Vec<RawMatch>> {
        use rayon::iter::{ParallelBridge, ParallelIterator};
        use std::sync::atomic::{AtomicUsize, Ordering};

        keyhog_sources::reset_skipped_over_max_size();
        #[cfg(feature = "binary")]
        keyhog_sources::reset_binary_counters();

        let progress_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let progress_handle = if show_progress && !self.args.stream {
            let done = Arc::clone(&progress_done);
            let started_t = Instant::now();
            Some(std::thread::spawn(move || {
                super::super::reporting::progress_ticker(done, started_t)
            }))
        } else {
            None
        };

        let incremental_path = self.incremental_cache_path();
        let scanner = Arc::clone(&self.scanner);
        let explicit_backend = explicit_backend_override();
        let calibration_mode = std::env::var_os("KEYHOG_AUTOROUTE_CALIBRATE").is_some();
        let active_router = if let Some(backend) = explicit_backend {
            ActiveBackendRouter::Explicit(backend)
        } else if calibration_mode {
            ActiveBackendRouter::Measured(Arc::new(Mutex::new(self.measured_backend_router())))
        } else {
            ActiveBackendRouter::Cached(self.cached_backend_router())
        };
        let routing_error = Arc::new(Mutex::new(None));

        let skipped_unchanged = Arc::new(AtomicUsize::new(0));
        let sc_t0 = Instant::now();

        // Bridge the source's `!Send` chunk iterator into a `Send` channel of
        // BATCHES that the global pool consumes via `par_bridge`. Reusing
        // `scan_coalesced` per batch keeps the finding set bit-identical to the
        // coalesced batch path (same scan entry, same phase-1 HS prefilter +
        // no-hit gating); parallelising ACROSS batches removes the single
        // scanner-thread bottleneck that pinned a 32-core box at ~9 cores.
        // `scan_coalesced` already calls the HS prefilter concurrently from its
        // own internal `par_iter`, so invoking it from several batch workers at
        // once is the same proven concurrency model, just wider. Batches are
        // small enough that the outer `par_bridge` keeps every core busy and
        // large enough to amortise scan_coalesced's per-batch phase/collect
        // cost. The drain thread only groups chunks + enforces the 512 MiB
        // ceiling; merkle hashing + scanning run in parallel in the consumer.
        //
        // Measured flat optimum on small-file filesystem corpora: 32 chunks
        // amortises the nested `scan_coalesced` phase costs better than 16
        // without the RSS bump seen at 64; buffering at roughly one batch per
        // four workers lets the drain thread stay ahead without letting
        // small-file corpora prefetch thousands of windows into RAM. Verified on
        // the full kernel tree (94k files, 32-core box): 4.25 s wall / 1833 % CPU
        // (~18 cores, 9.6x over single-thread), finding set byte-identical to the
        // coalesced batch path (7.12 s / 749 %).
        const FUSED_BATCH_DEFAULT: usize = 32;
        // FUSED_BATCH and the channel depth are Tier-A throughput knobs.
        // `scan_coalesced` runs its OWN two-phase `par_iter` over each batch, so
        // `par_bridge` over batches nests parallelism: the batch size trades
        // par_bridge cursor-mutex contention (smaller = more locking) against the
        // inner par_iter's per-batch fork-join barrier granularity (larger = more
        // work amortising each barrier). `KEYHOG_FUSED_BATCH` / `KEYHOG_FUSED_DEPTH`
        // override the defaults for host-specific tuning without a rebuild.
        let fused_batch = keyhog_core::env_config::usize_at_least_or_default(
            "KEYHOG_FUSED_BATCH",
            1,
            FUSED_BATCH_DEFAULT,
        );
        let fused_depth_default = rayon::current_num_threads()
            .saturating_add(3)
            .saturating_div(4)
            .clamp(2, 8);
        let fused_depth = keyhog_core::env_config::usize_at_least_or_default(
            "KEYHOG_FUSED_DEPTH",
            1,
            fused_depth_default,
        );
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<keyhog_core::Chunk>>(fused_depth);
        let drain = std::thread::spawn(move || {
            let mut batch: Vec<keyhog_core::Chunk> = Vec::with_capacity(fused_batch);
            'sources: for source in &sources {
                // Per-source outcome (see the non-fused path): a source that
                // yields zero chunks AND errors failed entirely; tracked so a
                // failed remote scan isn't masked by a clean local one.
                let mut src_chunks = 0usize;
                let mut src_errored = false;
                for chunk_result in source.chunks() {
                    match chunk_result {
                        Ok(c) if c.data.len() <= 512 * 1024 * 1024 => {
                            src_chunks += 1;
                            batch.push(c);
                            if batch.len() >= fused_batch {
                                if tx.send(std::mem::take(&mut batch)).is_err() {
                                    break 'sources;
                                }
                                batch = Vec::with_capacity(fused_batch);
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
            if !batch.is_empty() {
                let _ = tx.send(batch); // LAW10: unused-binding marker; no runtime effect, not a fallback
            }
        });

        let merkle_ref = merkle.as_ref();
        let skipped_ref = &skipped_unchanged;
        let scanner_ref = scanner.as_ref();
        let routing_error_ref = Arc::clone(&routing_error);

        let findings: Vec<RawMatch> = rx
            .into_iter()
            .par_bridge()
            .flat_map_iter(|batch| {
                let route_failed = match routing_error_ref.lock() {
                    Ok(guard) => guard.is_some(),
                    Err(poisoned) => poisoned.into_inner().is_some(),
                };
                if route_failed {
                    return Vec::new();
                }

                // Incremental skip (parallel across batches): hash each chunk
                // and drop the ones the merkle index already has unchanged.
                // Mirrors the coalesced batch producer: record metadata for every chunk
                // seen (changed or not); `finalize_incremental` later forgets
                // any path that produced a finding.
                let batch: Vec<keyhog_core::Chunk> = if let Some(idx) = merkle_ref {
                    batch
                        .into_iter()
                        .filter(|c| {
                            let Some(path_str) = c.metadata.path.as_deref() else {
                                return true;
                            };
                            let path = std::path::PathBuf::from(path_str);
                            let unchanged = idx.record_chunk_and_check_unchanged(
                                path,
                                c.metadata.mtime_ns.unwrap_or(0), // LAW10: empty/absent => documented numeric default, recall-safe
                                c.metadata.size_bytes.unwrap_or(0), // LAW10: empty/absent => documented numeric default, recall-safe
                                c.data.as_bytes(),
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

                // Normal fused filesystem scanning is cache-only: no probes,
                // no guesses. In explicit calibration mode it uses the measured
                // router on the SAME fused batch shape normal scans request, so
                // persisted decisions cover the production runtime key.
                let selected_backend = match &active_router {
                    ActiveBackendRouter::Explicit(backend) => Ok(*backend),
                    ActiveBackendRouter::Measured(router) => {
                        let mut router = match router.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        router.choose(scanner_ref, None, &batch)
                    }
                    ActiveBackendRouter::Cached(router) => router.choose(None, &batch),
                };

                let backend = match selected_backend {
                    Ok(backend) => backend,
                    Err(error) => {
                        match routing_error_ref.lock() {
                            Ok(mut guard) => {
                                if guard.is_none() {
                                    *guard = Some(error);
                                }
                            }
                            Err(poisoned) => {
                                let mut guard = poisoned.into_inner();
                                if guard.is_none() {
                                    *guard = Some(error);
                                }
                            }
                        }
                        return Vec::new();
                    }
                };
                let scanned_count = batch.len();
                let per_chunk = match backend {
                    keyhog_scanner::hw_probe::ScanBackend::Gpu
                    | keyhog_scanner::hw_probe::ScanBackend::MegaScan => {
                        tracing::debug!(
                            target: "keyhog::routing",
                            backend = backend.label(),
                            batch_bytes = batch.iter().map(|c| c.data.len() as u64).sum::<u64>(),
                            chunks = scanned_count,
                            "fused batch dispatched to GPU megakernel",
                        );
                        crate::GPU_SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                        scanner_ref.scan_chunks_with_backend(
                            &batch,
                            keyhog_scanner::hw_probe::ScanBackend::Gpu,
                        )
                    }
                    keyhog_scanner::hw_probe::ScanBackend::CpuFallback => scanner_ref
                        .scan_chunks_with_backend(
                            &batch,
                            keyhog_scanner::hw_probe::ScanBackend::CpuFallback,
                        ),
                    _ => scanner_ref.scan_coalesced(&batch),
                };
                crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);

                let mut out: Vec<RawMatch> = Vec::new();
                let mut batch_findings = 0usize;
                for chunk_findings in per_chunk {
                    batch_findings += chunk_findings.len();
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
        let _ = drain.join(); // LAW10: unused-binding marker; no runtime effect, not a fallback

        let routing_error = match routing_error.lock() {
            Ok(mut guard) => guard.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        if let Some(error) = routing_error {
            progress_done.store(true, Ordering::Relaxed);
            if let Some(h) = progress_handle {
                let _ = h.join(); // LAW10: unused-binding marker; no runtime effect, not a fallback
            }
            return Err(error.into());
        }

        if std::env::var("KH_PERF").is_ok() {
            eprintln!(
                "KH_PERF scan_sources_fused: wall={:.2}s findings={} scanned={} fused_batch={} fused_depth={}",
                sc_t0.elapsed().as_secs_f64(),
                findings.len(),
                crate::SCANNED_CHUNKS.load(Ordering::Relaxed),
                fused_batch,
                fused_depth,
            );
        }
        // Same operator-facing profiler dump as the streaming path: the fused
        // orchestrator is the other scan mode, so the `KEYHOG_PROFILE` gates
        // must surface here too (otherwise the profiler is dead on fused runs).
        if std::env::var("KEYHOG_PROFILE").as_deref() == Ok("1") {
            keyhog_scanner::profile_dump("keyhog scan");
        }
        if std::env::var("KEYHOG_PROFILE_SCANINNER").as_deref() == Ok("1") {
            keyhog_scanner::scan_inner_profile_dump();
        }

        progress_done.store(true, Ordering::Relaxed);
        if let Some(h) = progress_handle {
            let _ = h.join(); // LAW10: unused-binding marker; no runtime effect, not a fallback
        }

        let skipped_unchanged = skipped_unchanged.load(Ordering::Relaxed);
        self.finalize_incremental(
            merkle.as_ref(),
            incremental_path.as_deref(),
            skipped_unchanged,
            &findings,
        );

        Ok(findings)
    }
}
