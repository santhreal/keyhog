//! Fused filesystem read+scan dispatch path.

use super::backend::{
    backend_requires_coalesced_batch_pipeline, AutorouteRoutingError, CachedBackendRouter,
    MeasuredBackendRouter,
};
use crate::orchestrator::ScanOrchestrator;
use crate::orchestrator_config::{autoroute_config_digest, fused_depth_default};
use anyhow::Result;
use keyhog_core::{RawMatch, Source};
use std::sync::{Arc, Mutex};
use std::time::Instant;

enum ActiveBackendRouter {
    Explicit(keyhog_scanner::hw_probe::ScanBackend),
    Cached(CachedBackendRouter),
    Measured(Arc<Mutex<MeasuredBackendRouter>>),
}

impl ActiveBackendRouter {
    fn quarantine_recovered_route(
        &self,
        selection: &super::backend::BackendSelection,
        recovery: &keyhog_scanner::BackendRecoveryReceipt,
    ) -> std::result::Result<(), AutorouteRoutingError> {
        if recovery.is_phase1_admission_recovery() {
            return Ok(());
        }
        match self {
            Self::Explicit(_) => Ok(()),
            Self::Cached(router) => router.quarantine_recovered_route(selection, recovery),
            Self::Measured(router) => {
                let mut router = match router.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                router.quarantine_recovered_route(selection, recovery)
            }
        }
    }
}

impl ScanOrchestrator {
    /// Decide whether a scan runs on the fused parallel read+scan path.
    ///
    /// Engaged for filesystem and bounded-window stdin sources unless the
    /// operator explicitly forced a GPU backend:
    /// * **GPU forced by the user** keeps the coalesced per-batch
    ///   pipeline so `gpu_parity` and the large-buffer dispatch are untouched.
    ///   Default/auto scans stay fused. Persisted autoroute decisions are
    ///   consumed per fused batch, where the exact workload key is known, so a
    ///   GPU decision for one bucket cannot disable fused scanning globally.
    /// * **Other non-filesystem sources** may emit *gapless* chunks where
    ///   `scan_chunk_boundaries` is load-bearing. Stdin is eligible because its
    ///   bounded windows overlap by the same 128 KiB used by filesystem
    ///   windows; seam-straddling secrets are therefore present in one chunk.
    /// * `--batch-pipeline` forces the coalesced batch path (A/B + escape hatch).
    pub(super) fn should_use_fused_pipeline(&self, sources: &[Box<dyn Source>]) -> bool {
        if self.effective_config.batch_pipeline {
            return false;
        }
        let explicit = self.effective_config.backend_override;
        // Explicit GPU runs on the coalesced batch pipeline for diagnostics and
        // large-buffer parity. Auto GPU is a per-batch autoroute decision inside
        // the fused path, never a global switch based on another bucket.
        if backend_requires_coalesced_batch_pipeline(explicit) {
            return false;
        }
        !sources.is_empty()
            && sources.iter().all(|source| {
                let source = source.as_any();
                source.is::<keyhog_sources::FilesystemSource>()
                    || source.is::<keyhog_sources::StdinSource>()
                    || source.is::<keyhog_sources::ConfiguredStdinSource>()
                    || source.is::<keyhog_sources::BufferedStdinSource>()
            })
    }

    fn cached_backend_router(&self) -> CachedBackendRouter {
        let (hw_caps, pattern_count, rules_digest, config_digest) = self.autoroute_router_inputs();
        CachedBackendRouter::new(
            hw_caps,
            pattern_count,
            rules_digest,
            config_digest,
            self.effective_config.gpu_runtime_policy
                != keyhog_scanner::gpu::GpuRuntimePolicy::Disabled,
            Ok(self.effective_config.autoroute_cache_path.clone()),
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
            self.effective_config.gpu_runtime_policy
                != keyhog_scanner::gpu::GpuRuntimePolicy::Disabled,
            self.effective_config.autoroute_gpu,
            self.effective_config.autoroute_calibration,
            Ok(self.effective_config.autoroute_cache_path.clone()),
            self.autoroute_measurement_observer.clone(),
            self.scanner.as_ref(),
        )
    }

    fn autoroute_router_inputs(
        &self,
    ) -> (keyhog_scanner::hw_probe::HardwareCaps, usize, String, u64) {
        let hw_caps = keyhog_scanner::hw_probe::probe_hardware().clone();
        let pattern_count = self.scanner.runtime_status().pattern_count;
        let config_digest = autoroute_config_digest(&self.effective_config);
        let rules_digest = self.detector_rules_digest.clone();
        (hw_caps, pattern_count, rules_digest, config_digest)
    }

    /// Fused parallel read+scan: a dedicated reader fills one bounded batch
    /// while `scan_coalesced` spreads the active batch over the global Rayon
    /// pool. Source I/O and scanning overlap without retaining one source batch
    /// per worker.
    pub(super) fn scan_sources_fused(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::MerkleIndex>>,
        incremental_path: Option<std::path::PathBuf>,
    ) -> Result<Vec<RawMatch>> {
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

        let scanner = Arc::clone(&self.scanner);
        let explicit_backend = self.effective_config.backend_override;
        let calibration_mode = self.effective_config.autoroute_calibration;
        let recover_automatic_backend_faults = super::automatic_backend_recovery_allowed(
            explicit_backend,
            calibration_mode,
            self.effective_config.gpu_runtime_policy,
        );
        let active_router = if let Some(backend) = explicit_backend {
            ActiveBackendRouter::Explicit(backend)
        } else if calibration_mode {
            ActiveBackendRouter::Measured(Arc::new(Mutex::new(self.measured_backend_router())))
        } else {
            ActiveBackendRouter::Cached(self.cached_backend_router())
        };
        let routing_error = Arc::new(Mutex::new(None));

        let skipped_unchanged = Arc::new(AtomicUsize::new(0));

        // Bridge the source's `!Send` chunk iterator into one bounded queued
        // batch. `scan_coalesced` already parallelizes both scan phases across
        // the global worker pool, so consuming batches serially preserves full
        // inner parallelism without nested `par_bridge` workers each retaining
        // another source batch and its scan scratch.
        //
        // The count and byte ceilings trade fork/join amortization against
        // resident source bytes. Explicit CLI/TOML config owns the count and
        // queue depth so effective config and autoroute identity cannot drift.
        let fused_batch = self.effective_config.fused_batch;
        let fused_depth = self
            .effective_config
            .fused_depth
            .unwrap_or_else(|| fused_depth_default(rayon::current_num_threads())); // LAW10: absent fused-depth config => documented worker-derived default, surfaced by effective config as auto and hashed through thread/hardware identity; recall-safe throughput default
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<keyhog_core::Chunk>>(fused_depth);
        let drain_skipped_unchanged = Arc::clone(&skipped_unchanged);
        let profile_runtime = keyhog_profile::current_runtime();
        let drain_profile_runtime = profile_runtime.clone();
        let drain = std::thread::spawn(move || {
            let _profile_context = drain_profile_runtime
                .as_ref()
                .map(keyhog_profile::Runtime::enter);
            let mut batch: Vec<keyhog_core::Chunk> = Vec::with_capacity(fused_batch);
            // Running text size of `batch`. The cut below is byte-aware as well
            // as count-aware because `fused_batch` alone describes wildly
            // different amounts of memory per regime: 32 chunks is ~128 KiB of
            // small source files but ~32 MiB of 1 MiB large-file windows. Every
            // bound between here and the workers is counted in CHUNKS (channel
            // depth `fused_depth`, plus one batch resident per worker), so on a
            // large file those counts described over a gigabyte of headroom and
            // handed out only ~11 work units for a 300 MiB file on 32 cores.
            let mut batch_bytes = 0usize;
            let mut route_state = super::BatchRouteState::default();
            'sources: for source in &sources {
                let source_keeps_chunk_identities_contiguous =
                    source.chunk_identities_are_contiguous();
                // Per-source outcome (see the non-fused path): a source that
                // yields zero chunks AND errors failed entirely; tracked so a
                // failed remote scan isn't masked by a clean local one.
                let mut src_chunks = 0usize;
                let mut src_errored = false;
                let mut chunks = {
                    let _profile_span = keyhog_profile::span(keyhog_profile::Stage::SourceWalk);
                    source.chunks()
                };
                loop {
                    let chunk_result = {
                        let _profile_span = keyhog_profile::span(keyhog_profile::Stage::SourceRead);
                        match chunks.next() {
                            Some(chunk_result) => chunk_result,
                            None => break,
                        }
                    };
                    let super::ClassifiedSourceChunk::Scan(c) = super::classify_source_chunk(
                        chunk_result,
                        &mut src_chunks,
                        &mut src_errored,
                    ) else {
                        continue;
                    };
                    if route_state.should_split_before(&c, source_keeps_chunk_identities_contiguous)
                    {
                        let send_result = {
                            let _profile_span =
                                keyhog_profile::span(keyhog_profile::Stage::SourceQueueWait);
                            tx.send(std::mem::take(&mut batch))
                        };
                        route_state.clear();
                        batch_bytes = 0;
                        if send_result.is_err() {
                            break 'sources;
                        }
                        batch = Vec::with_capacity(fused_batch);
                    }
                    route_state.push(&c);
                    batch_bytes = batch_bytes.saturating_add(c.data.len());
                    batch.push(c);
                    if batch.len() >= fused_batch
                        || batch_bytes >= crate::orchestrator_config::FUSED_BATCH_BYTES
                    {
                        let send_result = {
                            let _profile_span =
                                keyhog_profile::span(keyhog_profile::Stage::SourceQueueWait);
                            tx.send(std::mem::take(&mut batch))
                        };
                        route_state.clear();
                        batch_bytes = 0;
                        if send_result.is_err() {
                            break 'sources;
                        }
                        batch = Vec::with_capacity(fused_batch);
                    }
                }
                super::finalize_source_outcome(src_chunks, src_errored);
                let source_skipped = super::filesystem_source_skipped_unchanged(source.as_ref());
                if source_skipped > 0 {
                    drain_skipped_unchanged.fetch_add(source_skipped, Ordering::Relaxed);
                }
                // Same per-partition workflow evidence as the coalesced
                // producer: the drain thread visits sources sequentially, so
                // the aggregate-counter delta at each boundary is exactly
                // this source's contribution (see the coalesced path).
                if crate::operator_profile_active() {
                    let (bytes, units) = keyhog_profile::take_input_totals();
                    super::super::workflow_state::record_source_partition(
                        source.name(),
                        units,
                        bytes,
                    );
                }
            }
            if !batch.is_empty() {
                let _profile_span = keyhog_profile::span(keyhog_profile::Stage::SourceQueueWait);
                let _ = tx.send(batch); // LAW10: unused-binding marker; no runtime effect, not a fallback
            }
        });

        let merkle_ref = merkle.as_ref();
        let skipped_ref = &skipped_unchanged;
        let scanner_ref = scanner.as_ref();
        let routing_error_ref = Arc::clone(&routing_error);

        let findings: Vec<RawMatch> = rx
            .into_iter()
            .flat_map(|batch| {
                let _profile_context = profile_runtime.as_ref().map(keyhog_profile::Runtime::enter);
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
                            let _profile_span =
                                keyhog_profile::span(keyhog_profile::Stage::IncrementalLookup);
                            let unchanged = idx.record_chunk_path_at_offset_and_check_unchanged(
                                std::path::Path::new(path_str),
                                c.metadata.base_offset as u64,
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
                if super::batch_has_no_scan_bytes(&batch) {
                    crate::SCANNED_CHUNKS.fetch_add(batch.len(), Ordering::Relaxed);
                    crate::SCANNED_BYTES.fetch_add(
                        batch
                            .iter()
                            .map(|chunk| chunk.data.len() as u64)
                            .sum::<u64>(),
                        Ordering::Relaxed,
                    );
                    return Vec::new();
                }

                // Normal fused filesystem scanning is cache-only: no probes,
                // no guesses. In explicit calibration mode it uses the measured
                // router on the SAME fused batch shape normal scans request, so
                // persisted decisions cover the production runtime key.
                let backend_select_span =
                    keyhog_profile::span(keyhog_profile::Stage::BackendSelect);
                let selected = match &active_router {
                    ActiveBackendRouter::Explicit(backend) => {
                        Ok(super::backend::BackendSelection {
                            backend: *backend,
                            phase1_plan: (!backend.is_gpu())
                                .then(|| scanner_ref.phase1_admission_plan(&batch)),
                            execution_route: scanner_ref.execution_route_for_backend(*backend),
                            recovery_plan: None,
                            runtime_route: None,
                            autoroute_recovery: None,
                        })
                    }
                    ActiveBackendRouter::Measured(router) => {
                        let mut router = match router.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        router.choose_with_plan(scanner_ref, None, &batch)
                    }
                    ActiveBackendRouter::Cached(router) => {
                        router.choose_with_plan(scanner_ref, None, &batch)
                    }
                };
                drop(backend_select_span);

                let selection = match selected {
                    Ok(selection) => selection,
                    Err(error) => {
                        record_routing_error(&routing_error_ref, error);
                        return Vec::new();
                    }
                };
                let backend = selection.backend;
                let scanned_count = batch.len();
                // The shared selected-batch outcome distinguishes real GPU
                // execution from a route completed by another calibrated peer.
                match backend {
                    keyhog_scanner::hw_probe::ScanBackend::GpuCuda
                    | keyhog_scanner::hw_probe::ScanBackend::GpuMetal
                    | keyhog_scanner::hw_probe::ScanBackend::GpuWgpu => {
                        tracing::debug!(
                            target: "keyhog::routing",
                            backend = backend.label(),
                            batch_bytes = batch.iter().map(|c| c.data.len() as u64).sum::<u64>(),
                            chunks = scanned_count,
                            "fused batch dispatched to GPU region presence",
                        );
                    }
                    keyhog_scanner::hw_probe::ScanBackend::CpuFallback
                    | keyhog_scanner::hw_probe::ScanBackend::SimdCpu => {}
                    backend => {
                        record_routing_error(
                            &routing_error_ref,
                            AutorouteRoutingError::unsupported_backend(backend),
                        );
                        return Vec::new();
                    }
                }
                let outcome = match super::scan_selected_batch(
                    scanner_ref,
                    &batch,
                    backend,
                    selection.phase1_plan.as_ref(),
                    selection.execution_route,
                    selection
                        .recovery_plan
                        .filter(|_| recover_automatic_backend_faults),
                ) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        record_routing_error(
                            &routing_error_ref,
                            AutorouteRoutingError::selected_backend_dispatch_failed(backend, error),
                        );
                        return Vec::new();
                    }
                };
                super::record_profiled_batch_route(
                    &batch,
                    explicit_backend.map_or("auto", keyhog_scanner::ScanBackend::label),
                    &selection,
                    &outcome,
                );
                if let Some(recovery) = outcome.recovery.as_ref() {
                    if let Err(error) =
                        active_router.quarantine_recovered_route(&selection, recovery)
                    {
                        record_routing_error(&routing_error_ref, error);
                        return Vec::new();
                    }
                }
                if let Some(recovery) = selection.autoroute_recovery.as_ref() {
                    super::record_completed_autoroute_state_recovery(&batch, backend, recovery);
                }
                crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                crate::SCANNED_BYTES.fetch_add(
                    batch
                        .iter()
                        .map(|chunk| chunk.data.len() as u64)
                        .sum::<u64>(),
                    Ordering::Relaxed,
                );
                // Count only a selected GPU dispatch that completed without a
                // degradation record. Degraded batches return a routing error
                // above and never contribute findings or GPU telemetry.
                if backend.is_gpu() && !outcome.recovered {
                    crate::GPU_SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
                }

                let out = {
                    let _profile_span = keyhog_profile::span(keyhog_profile::Stage::ResultMerge);
                    let mut per_chunk = outcome.per_chunk;
                    crate::inline_suppression::attach_inline_suppression_context(
                        &batch,
                        &mut per_chunk,
                    );

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
                };
                out
            })
            .collect();

        // Drain thread owns source iteration for the fused path. A panic here
        // means the scan saw only a prefix of the requested input; record the
        // same incomplete-scan state as scanner worker panics so report and
        // exit semantics cannot read as clean.
        if drain.join().is_err() {
            tracing::error!("fused source drain thread panicked mid-scan; results are incomplete");
            let _receipt = crate::record_scanner_panic();
            anyhow::bail!("fused source drain thread panicked mid-scan; results are incomplete");
        }

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
        if let ActiveBackendRouter::Measured(router) = &active_router {
            let commit = match router.lock() {
                Ok(mut guard) => guard.commit(),
                Err(poisoned) => poisoned.into_inner().commit(),
            };
            if let Err(error) = commit {
                progress_done.store(true, Ordering::Relaxed);
                if let Some(h) = progress_handle {
                    let _ = h.join(); // LAW10: unused-binding marker; no runtime effect, not a fallback
                }
                return Err(error.into());
            }
        }

        // Same operator-facing profiler drain as the streaming path. The
        // profiler owns the measurement switch and the wall clock; fused
        // dispatch only requests the report. A private `Instant` used to time
        // this region and print its own `perf-trace scan_sources_fused` line;
        // the wall it measured is the scan wall the profiler already records,
        // and the rest of that line was resolved config, not measurement.
        self.scanner.dump_profile_reports("keyhog scan");

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

fn record_routing_error(
    slot: &Arc<Mutex<Option<AutorouteRoutingError>>>,
    error: AutorouteRoutingError,
) {
    match slot.lock() {
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
}
