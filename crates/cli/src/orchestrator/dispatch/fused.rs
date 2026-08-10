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

const STDIN_FUSED_BATCH_BYTES: usize = 2 * 1024 * 1024;

const REPEATED_WINDOW_CACHE_CAP: usize = 8;

struct RepeatedWindowCacheEntry {
    fingerprint: [u8; 32],
    data: keyhog_core::SensitiveString,
    metadata: keyhog_core::ChunkMetadata,
    findings: Vec<RawMatch>,
}

struct RepeatedWindowCache {
    entries: std::collections::VecDeque<RepeatedWindowCacheEntry>,
}

impl RepeatedWindowCache {
    fn new() -> Self {
        Self {
            entries: std::collections::VecDeque::with_capacity(REPEATED_WINDOW_CACHE_CAP),
        }
    }

    fn lookup(
        &mut self,
        batch: &[keyhog_core::Chunk],
        fingerprint: [u8; 32],
    ) -> Option<Vec<RawMatch>> {
        let chunk = repeated_window_chunk(batch)?;
        let position = self.entries.iter().position(|entry| {
            entry.fingerprint == fingerprint
                && repeated_window_metadata_matches(&entry.metadata, &chunk.metadata)
                && entry.data.as_bytes() == chunk.data.as_bytes()
        })?;
        let entry = self.entries.remove(position)?;
        let replay =
            rebase_repeated_window_findings(&entry.findings, &entry.metadata, &chunk.metadata);
        self.entries.push_back(entry);
        replay
    }

    fn insert(&mut self, chunk: keyhog_core::Chunk, fingerprint: [u8; 32], findings: &[RawMatch]) {
        if chunk.metadata.source_type.as_ref() != "filesystem/windowed" {
            return;
        }
        if let Some(position) = self.entries.iter().position(|entry| {
            entry.fingerprint == fingerprint
                && repeated_window_metadata_matches(&entry.metadata, &chunk.metadata)
                && entry.data.as_bytes() == chunk.data.as_bytes()
        }) {
            self.entries.remove(position);
        } else if self.entries.len() == REPEATED_WINDOW_CACHE_CAP {
            self.entries.pop_front();
        }
        self.entries.push_back(RepeatedWindowCacheEntry {
            fingerprint,
            data: chunk.data,
            metadata: chunk.metadata,
            findings: findings.to_vec(),
        });
    }
}

fn repeated_window_chunk(batch: &[keyhog_core::Chunk]) -> Option<&keyhog_core::Chunk> {
    let [chunk] = batch else {
        return None;
    };
    (chunk.metadata.source_type.as_ref() == "filesystem/windowed").then_some(chunk)
}

fn repeated_window_fingerprint(batch: &[keyhog_core::Chunk]) -> Option<[u8; 32]> {
    const SAMPLE_COUNT: usize = 8;
    const SAMPLE_BYTES: usize = 64;

    let data = repeated_window_chunk(batch)?.data.as_bytes();
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(data.len() as u64).to_le_bytes());
    if data.len() <= SAMPLE_COUNT * SAMPLE_BYTES {
        hasher.update(data);
    } else {
        let max_start = data.len() - SAMPLE_BYTES;
        for sample in 0..SAMPLE_COUNT {
            let start = max_start * sample / (SAMPLE_COUNT - 1);
            hasher.update(&data[start..start + SAMPLE_BYTES]);
        }
    }
    Some(*hasher.finalize().as_bytes())
}

fn repeated_window_batches_match(
    left: &[keyhog_core::Chunk],
    right: &[keyhog_core::Chunk],
) -> bool {
    let (Some(left), Some(right)) = (repeated_window_chunk(left), repeated_window_chunk(right))
    else {
        return false;
    };
    repeated_window_metadata_matches(&left.metadata, &right.metadata)
        && left.data.as_bytes() == right.data.as_bytes()
}

fn repeated_window_metadata_matches(
    left: &keyhog_core::ChunkMetadata,
    right: &keyhog_core::ChunkMetadata,
) -> bool {
    left.source_type == right.source_type
        && left.path == right.path
        && left.commit == right.commit
        && left.author == right.author
        && left.date == right.date
        && left.mtime_ns == right.mtime_ns
        && left.size_bytes == right.size_bytes
        && left.decoded_span == right.decoded_span
}

fn rebase_repeated_window_findings(
    findings: &[RawMatch],
    from: &keyhog_core::ChunkMetadata,
    to: &keyhog_core::ChunkMetadata,
) -> Option<Vec<RawMatch>> {
    findings
        .iter()
        .cloned()
        .map(|mut finding| {
            let relative_offset = finding.location.offset.checked_sub(from.base_offset)?;
            finding.location.offset = to.base_offset.checked_add(relative_offset)?;
            if let Some(line) = finding.location.line {
                let relative_line = line.checked_sub(from.base_line)?;
                finding.location.line = Some(to.base_line.checked_add(relative_line)?);
            }
            finding.location.source = Arc::clone(&to.source_type);
            finding.location.file_path = to.path.clone();
            finding.location.commit = to.commit.clone();
            finding.location.author = to.author.clone();
            finding.location.date = to.date.clone();
            Some(finding)
        })
        .collect()
}

fn record_repeated_window_replay(batch: &[keyhog_core::Chunk], findings: &[RawMatch]) {
    use std::sync::atomic::Ordering;

    crate::TOTAL_CHUNKS.fetch_add(batch.len(), Ordering::Relaxed);
    crate::SCANNED_CHUNKS.fetch_add(batch.len(), Ordering::Relaxed);
    crate::SCANNED_BYTES.fetch_add(
        batch
            .iter()
            .map(|chunk| chunk.data.len() as u64)
            .sum::<u64>(),
        Ordering::Relaxed,
    );
    crate::FINDINGS_COUNT.fetch_add(findings.len(), Ordering::Relaxed);
}

fn is_stdin_source(source: &dyn Source) -> bool {
    let source = source.as_any();
    source.is::<keyhog_sources::StdinSource>()
        || source.is::<keyhog_sources::ConfiguredStdinSource>()
        || source.is::<keyhog_sources::BufferedStdinSource>()
}

fn supports_fused_dispatch(source: &dyn Source) -> bool {
    source.as_any().is::<keyhog_sources::FilesystemSource>() || is_stdin_source(source)
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
            && sources
                .iter()
                .all(|source| supports_fused_dispatch(source.as_ref()))
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

    /// Fused bounded read+scan: a dedicated reader emits 1 MiB batches.
    /// Explicit CPU and SIMD routes let Rayon workers retire independent
    /// batches concurrently; automatic and GPU-capable routing keeps one active
    /// batch so resident accelerator state is never oversubscribed.
    pub(super) fn scan_sources_fused(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::MerkleIndex>>,
        incremental_path: Option<std::path::PathBuf>,
    ) -> Result<Vec<RawMatch>> {
        use rayon::prelude::*;
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

        // Bridge the source's `!Send` chunk iterator into a bounded queue.
        // The consumer retires explicit CPU/SIMD batches in a separate bounded
        // wave: at most four 1 MiB filesystem batches are resident there, while
        // the rendezvous channel prevents another completed batch from queuing.
        //
        // The count and byte ceilings trade fork/join amortization against
        // resident source bytes. Explicit CLI/TOML config owns the count and
        // queue depth so effective config and autoroute identity cannot drift.
        let fused_batch = self.effective_config.fused_batch;
        // Stdin windows are already bounded to 1 MiB. Pair adjacent windows so
        // `scan_coalesced` amortizes fork/join and gate setup while the default
        // rendezvous channel keeps the live source payload below 3 MiB.
        let fused_batch_bytes = if sources
            .iter()
            .all(|source| is_stdin_source(source.as_ref()))
        {
            STDIN_FUSED_BATCH_BYTES
        } else {
            crate::orchestrator_config::FUSED_BATCH_BYTES
        };
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
            let initial_batch_capacity = fused_batch.min(64);
            let mut batch: Vec<keyhog_core::Chunk> = Vec::with_capacity(initial_batch_capacity);
            // Running text size of `batch`. The byte ceiling is authoritative:
            // tiny files coalesce until one substantial work unit is ready,
            // while a 1 MiB source window dispatches alone. Reserving only the
            // first 64 rows avoids paying the 1024-row tiny-file capacity for
            // large-file and stdin batches.
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
                super::super::run::release_current_allocator_arena();
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
                        batch = Vec::with_capacity(initial_batch_capacity);
                    }
                    route_state.push(&c);
                    batch_bytes = batch_bytes.saturating_add(c.data.len());
                    batch.push(c);
                    if batch.len() >= fused_batch || batch_bytes >= fused_batch_bytes {
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
                        batch = Vec::with_capacity(initial_batch_capacity);
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

        let scan_batch = |batch: Vec<keyhog_core::Chunk>| {
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
            let backend_select_span = keyhog_profile::span(keyhog_profile::Stage::BackendSelect);
            let selected = match &active_router {
                ActiveBackendRouter::Explicit(backend) => Ok(super::backend::BackendSelection {
                    backend: *backend,
                    phase1_plan: (!backend.is_gpu())
                        .then(|| scanner_ref.phase1_admission_plan_for_backend(&batch, *backend)),
                    execution_route: scanner_ref.execution_route_for_backend(*backend),
                    recovery_plan: None,
                    runtime_route: None,
                    autoroute_recovery: None,
                }),
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
                if let Err(error) = active_router.quarantine_recovered_route(&selection, recovery) {
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
        };
        let findings: Vec<RawMatch> = if matches!(
            explicit_backend,
            Some(
                keyhog_scanner::hw_probe::ScanBackend::CpuFallback
                    | keyhog_scanner::hw_probe::ScanBackend::SimdCpu
            )
        ) {
            let lane_width =
                crate::orchestrator_config::fused_cpu_wave_width(rayon::current_num_threads());
            let mut batches = rx.into_iter();
            let mut findings = Vec::new();
            let mut repeated_windows = merkle_ref.is_none().then(RepeatedWindowCache::new);
            loop {
                let wave: Vec<_> = batches.by_ref().take(lane_width).collect();
                if wave.is_empty() {
                    break;
                }
                let mut wave_findings: Vec<Option<Vec<RawMatch>>> =
                    (0..wave.len()).map(|_| None).collect();
                let mut misses: Vec<(
                    usize,
                    Vec<keyhog_core::Chunk>,
                    Option<[u8; 32]>,
                    Vec<(usize, Vec<keyhog_core::Chunk>)>,
                )> = Vec::with_capacity(wave.len());
                for (index, batch) in wave.into_iter().enumerate() {
                    let fingerprint = repeated_windows
                        .as_ref()
                        .and_then(|_| repeated_window_fingerprint(&batch));
                    let replay = match (repeated_windows.as_mut(), fingerprint) {
                        (Some(cache), Some(fingerprint)) => cache.lookup(&batch, fingerprint),
                        _ => None,
                    };
                    if let Some(replay) = replay {
                        record_repeated_window_replay(&batch, &replay);
                        wave_findings[index] = Some(replay);
                        continue;
                    }
                    if let Some(fingerprint) = fingerprint {
                        if let Some((_, _, _, duplicates)) =
                            misses.iter_mut().find(|(_, representative, candidate, _)| {
                                *candidate == Some(fingerprint)
                                    && repeated_window_batches_match(representative, &batch)
                            })
                        {
                            duplicates.push((index, batch));
                            continue;
                        }
                    }
                    misses.push((index, batch, fingerprint, Vec::new()));
                }
                let scanned: Vec<_> = misses
                    .into_par_iter()
                    .map(|(index, batch, fingerprint, duplicates)| {
                        let cache_anchor = repeated_window_chunk(&batch).cloned();
                        (
                            index,
                            cache_anchor,
                            fingerprint,
                            duplicates,
                            scan_batch(batch),
                        )
                    })
                    .collect();
                for (index, cache_anchor, fingerprint, duplicates, batch_findings) in scanned {
                    if let (Some(cache), Some(anchor), Some(fingerprint)) =
                        (repeated_windows.as_mut(), cache_anchor, fingerprint)
                    {
                        cache.insert(anchor, fingerprint, &batch_findings);
                    }
                    wave_findings[index] = Some(batch_findings);
                    for (duplicate_index, duplicate) in duplicates {
                        let replay = match (repeated_windows.as_mut(), fingerprint) {
                            (Some(cache), Some(fingerprint)) => {
                                cache.lookup(&duplicate, fingerprint)
                            }
                            _ => None,
                        };
                        let duplicate_findings = if let Some(replay) = replay {
                            record_repeated_window_replay(&duplicate, &replay);
                            replay
                        } else {
                            scan_batch(duplicate)
                        };
                        wave_findings[duplicate_index] = Some(duplicate_findings);
                    }
                }
                findings.extend(wave_findings.into_iter().flatten().flatten());
            }
            findings
        } else {
            rx.into_iter().flat_map(scan_batch).collect()
        };

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
