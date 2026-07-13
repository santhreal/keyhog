//! Scan dispatch: producer/scanner pipeline and backend routing.
//!
//! NOTE: `--stream` previews are NOT emitted here. They are emitted from the
//! run loop (`run.rs`) against the RESOLVED `VerifiedFinding` report stream,
//! after `filter_and_resolve` / suppression / `--min-confidence`, so a streamed
//! `[stream]` line always corresponds to a reported finding (stream count ==
//! report count). Emitting on raw scanner matches here previewed findings the
//! report later dropped (a correctness/coherence bug (AUD-testing_dogfood-1)).

use super::ScanOrchestrator;
use crate::orchestrator_config::autoroute_config_digest;
mod backend;
mod fused;
mod pipeline;
use anyhow::Result;
pub(crate) use backend::backend_requires_coalesced_batch_pipeline_for_test;
pub(crate) use backend::inspect_autoroute_cache;
pub(crate) use backend::CachedBackendRouter;
use backend::{is_gpu_backend, AutorouteRoutingError, MeasuredBackendRouter};
use keyhog_core::{Chunk, RawMatch, Source};
use keyhog_scanner::hw_probe::{HardwareCaps, ScanBackend};
use keyhog_scanner::CompiledScanner;
use pipeline::{coalesced_pipeline_plan, CoalescedPipelinePlan};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

/// Single owner of the per-chunk scan ceiling. Enforced by the in-process
/// coalesced pipeline (below) AND the daemon path (`daemon::server`), so both
/// refuse the same size and neither refusal string can drift from the limit.
pub(crate) const COALESCED_CHUNK_SCAN_CEILING_BYTES: usize = 512 * 1024 * 1024;
/// The scan ceiling in MiB, derived from the byte constant so the operator-facing
/// skip messages can never name a different size than the limit actually enforced.
pub(crate) const COALESCED_CHUNK_SCAN_CEILING_MB: usize =
    COALESCED_CHUNK_SCAN_CEILING_BYTES / (1024 * 1024);

pub(super) fn record_oversized_coalesced_chunk_skip(chunk: &Chunk) {
    let mb = chunk.data.len() / (1024 * 1024);
    let path = chunk.metadata.path.as_deref().unwrap_or("<unknown>"); // LAW10: absent path/field => display placeholder for REPORTING only; coverage gap still recorded
    eprintln!(
        "keyhog: WARNING: skipping chunk over {COALESCED_CHUNK_SCAN_CEILING_MB} MiB scan ceiling ({mb} MiB) at {path}; it was NOT scanned for secrets."
    );
    let _receipt = crate::record_source_error();
    tracing::warn!(
        path = %path,
        size_mb = mb,
        ceiling_mb = COALESCED_CHUNK_SCAN_CEILING_MB,
        "skipping chunk over scan ceiling"
    );
}

/// One classified `source.chunks()` item for the coalesced
/// ([`CoalescedProducer::produce_sources`]) and fused ([`fused`]) producer loops.
/// The shared FAIL-CLOSED bookkeeping, the oversized-chunk warning + coverage
/// receipt and the read-error receipt, lives in [`classify_source_chunk`] so the
/// two loops can NEVER drift on the scan-size ceiling or on which coverage
/// receipts fire (a drift there would silently under-account coverage on one
/// path). They differ ONLY in how a scannable chunk is batched onward.
pub(super) enum ClassifiedSourceChunk {
    /// Within the scan-size ceiling: the caller must batch/scan it.
    Scan(Chunk),
    /// Oversized (warned + receipted) or a read error (warned + receipted)
    /// already fully accounted; the caller does nothing further.
    Skip,
}

/// Classify one `source.chunks()` item, performing the shared fail-closed
/// bookkeeping, and advance the per-source counters. `src_chunks` counts every
/// chunk the source yielded (scannable OR oversized-skipped); `src_errored`
/// records that at least one read error occurred, together they drive
/// [`finalize_source_outcome`]'s total-failure decision.
pub(super) fn classify_source_chunk(
    chunk_result: std::result::Result<Chunk, keyhog_core::SourceError>,
    src_chunks: &mut usize,
    src_errored: &mut bool,
) -> ClassifiedSourceChunk {
    match chunk_result {
        Ok(c) if c.data.len() <= COALESCED_CHUNK_SCAN_CEILING_BYTES => {
            *src_chunks += 1;
            ClassifiedSourceChunk::Scan(c)
        }
        Ok(c) => {
            *src_chunks += 1;
            record_oversized_coalesced_chunk_skip(&c);
            ClassifiedSourceChunk::Skip
        }
        Err(e) => {
            let _receipt = crate::record_source_error();
            *src_errored = true;
            tracing::warn!("source: {e}");
            ClassifiedSourceChunk::Skip
        }
    }
}

/// Finalize a source after its chunk stream drains: a source that yielded ZERO
/// chunks AND errored failed entirely, recorded via `record_failed_source` so
/// `run()` fails closed rather than reporting "clean" off another source's data.
/// A source that produced ANY chunk, even one later skipped as oversized, is a
/// partial success, not a total failure. Single owner of this rule for both
/// producer loops.
pub(super) fn finalize_source_outcome(src_chunks: usize, src_errored: bool) {
    if src_chunks == 0 && src_errored {
        let _receipt = crate::record_failed_source();
    }
}

struct CoalescedScannerWorker {
    scanner: Arc<CompiledScanner>,
    router: CoalescedBatchRouter,
    perf_trace: bool,
}

enum CoalescedBatchRouter {
    Explicit(ScanBackend),
    Measured(MeasuredBackendRouter),
}

struct CoalescedMeasuredRouterConfig {
    hw_caps: HardwareCaps,
    pattern_count: usize,
    rules_digest: String,
    config_digest: u64,
    autoroute_gpu: bool,
    autoroute_calibration: bool,
    autoroute_cache_path: std::result::Result<Option<std::path::PathBuf>, String>,
}

impl CoalescedBatchRouter {
    fn choose(
        &mut self,
        scanner: &CompiledScanner,
        batch: &[Chunk],
    ) -> std::result::Result<ScanBackend, AutorouteRoutingError> {
        match self {
            Self::Explicit(backend) => Ok(*backend),
            Self::Measured(router) => router.choose(scanner, None, batch),
        }
    }

    fn commit(&mut self) -> std::result::Result<(), AutorouteRoutingError> {
        match self {
            Self::Explicit(_) => Ok(()),
            Self::Measured(router) => router.commit(),
        }
    }
}

impl CoalescedScannerWorker {
    fn explicit(scanner: Arc<CompiledScanner>, backend: ScanBackend, perf_trace: bool) -> Self {
        Self {
            scanner,
            router: CoalescedBatchRouter::Explicit(backend),
            perf_trace,
        }
    }

    fn measured(
        scanner: Arc<CompiledScanner>,
        config: CoalescedMeasuredRouterConfig,
        perf_trace: bool,
    ) -> Self {
        let router = MeasuredBackendRouter::new(
            config.hw_caps,
            config.pattern_count,
            config.rules_digest,
            config.config_digest,
            config.autoroute_gpu,
            config.autoroute_calibration,
            config.autoroute_cache_path,
            scanner.as_ref(),
        );
        Self {
            scanner,
            router: CoalescedBatchRouter::Measured(router),
            perf_trace,
        }
    }

    fn run(
        mut self,
        rx: std::sync::mpsc::Receiver<Vec<Chunk>>,
    ) -> std::result::Result<Vec<RawMatch>, AutorouteRoutingError> {
        let sc_t0 = std::time::Instant::now();
        let mut scan_dur = std::time::Duration::ZERO;
        let mut recv_dur = std::time::Duration::ZERO;
        let mut last_end = std::time::Instant::now();
        let mut findings: Vec<RawMatch> = Vec::new();

        for batch in rx {
            recv_dur += last_end.elapsed();
            if !batch.is_empty() {
                scan_dur += self.scan_nonempty_batch(&batch, &mut findings)?;
            }
            last_end = std::time::Instant::now();
        }

        self.router.commit()?;
        self.dump_perf_trace(sc_t0, scan_dur, recv_dur);
        self.scanner.dump_profile_reports("keyhog scan");
        Ok(findings)
    }

    fn scan_nonempty_batch(
        &mut self,
        batch: &[Chunk],
        findings: &mut Vec<RawMatch>,
    ) -> std::result::Result<std::time::Duration, AutorouteRoutingError> {
        let scan_start = std::time::Instant::now();
        let scanned_count = batch.len();
        if batch_has_no_scan_bytes(batch) {
            crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
            return Ok(scan_start.elapsed());
        }
        let chosen_backend = self.router.choose(self.scanner.as_ref(), batch)?;
        let chose_gpu = is_gpu_backend(chosen_backend);
        // Snapshot the scanner's runtime GPU-degrade counter BEFORE the GPU arm so
        // we can tell whether THIS batch actually executed on the GPU. Runtime
        // failure terminates in `require_selected_backend_stack`; the counter
        // check keeps GPU_SCANNED_CHUNKS honest for embedders that replace that
        // process boundary.
        let degrade_before = chose_gpu.then(|| self.scanner.gpu_degrade_count());
        let per_chunk = match chosen_backend {
            // The VYRE GpuLiteralSet region-presence route is the single on-GPU
            // trigger path. It owns backend acquisition and fails the selected
            // route if dispatch cannot remain on GPU, so both an explicit GPU
            // request and an autoroute-selected GPU batch land here.
            ScanBackend::Gpu => {
                let batch_bytes: u64 = batch.iter().map(|c| c.data.len() as u64).sum();
                tracing::debug!(
                    target: "keyhog::routing",
                    backend = "gpu",
                    batch_bytes,
                    chunks = scanned_count,
                    "batch dispatched (gpu region presence)",
                );
                self.scanner
                    .scan_chunks_with_backend(batch, ScanBackend::Gpu)
            }
            ScanBackend::CpuFallback => self
                .scanner
                .scan_chunks_with_backend(batch, ScanBackend::CpuFallback),
            ScanBackend::SimdCpu => self
                .scanner
                .scan_coalesced_with_backend(batch, ScanBackend::SimdCpu),
            backend => return Err(AutorouteRoutingError::unsupported_backend(backend)),
        };
        // Count the batch as GPU-scanned only if it was routed to the GPU AND the
        // scanner recorded no runtime degrade while dispatching it. A degrade
        // hard-fails the selected route; retaining the counter check also keeps
        // telemetry honest if an embedder replaces the process-exit boundary.
        let ran_on_gpu =
            degrade_before.is_some_and(|before| self.scanner.gpu_degrade_count() == before);
        append_scanned_batch_findings(findings, batch, per_chunk, scanned_count, ran_on_gpu);
        Ok(scan_start.elapsed())
    }

    fn dump_perf_trace(
        &self,
        started: std::time::Instant,
        scan_dur: std::time::Duration,
        recv_dur: std::time::Duration,
    ) {
        if !self.perf_trace {
            return;
        }
        let wall = started.elapsed().as_secs_f64().max(1e-9);
        eprintln!(
            "perf-trace scanner_thread: wall={:.2}s scan={:.2}s recv_wait={:.2}s (scan {:.0}%, recv_wait {:.0}%)",
            wall,
            scan_dur.as_secs_f64(),
            recv_dur.as_secs_f64(),
            100.0 * scan_dur.as_secs_f64() / wall,
            100.0 * recv_dur.as_secs_f64() / wall,
        );
    }
}

fn batch_has_no_scan_bytes(batch: &[Chunk]) -> bool {
    batch.iter().all(|chunk| chunk.data.is_empty())
}

fn append_scanned_batch_findings(
    findings: &mut Vec<RawMatch>,
    batch: &[Chunk],
    mut per_chunk: Vec<Vec<RawMatch>>,
    scanned_count: usize,
    ran_on_gpu: bool,
) {
    use std::sync::atomic::Ordering;

    crate::SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
    if ran_on_gpu {
        // Authoritative routing signal for the completion summary: this is the
        // single coalesced-pipeline path where chunks actually run on the GPU.
        crate::GPU_SCANNED_CHUNKS.fetch_add(scanned_count, Ordering::Relaxed);
    }
    let mut batch_findings = 0usize;
    crate::inline_suppression::attach_inline_suppression_context(batch, &mut per_chunk);
    for chunk_findings in per_chunk {
        batch_findings += chunk_findings.len();
        findings.extend(chunk_findings);
    }
    crate::FINDINGS_COUNT.fetch_add(batch_findings, Ordering::Relaxed);
}

struct CoalescedProducerOutcome {
    skipped_unchanged: usize,
}

pub(super) fn filesystem_source_skipped_unchanged(source: &dyn Source) -> usize {
    source
        .as_any()
        .downcast_ref::<keyhog_sources::FilesystemSource>()
        .map(keyhog_sources::FilesystemSource::skipped_unchanged_count)
        .unwrap_or(0) // LAW10: non-filesystem sources cannot have filesystem Merkle skips; zero is the exact typed count, recall-safe
}

struct CoalescedProgressTicker {
    done: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl CoalescedProgressTicker {
    fn spawn(enabled: bool) -> Self {
        let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handle = if enabled {
            let ticker_done = Arc::clone(&done);
            let started_t = Instant::now();
            Some(std::thread::spawn(move || {
                super::reporting::progress_ticker(ticker_done, started_t)
            }))
        } else {
            None
        };
        Self { done, handle }
    }

    fn stop(self) {
        self.done.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle {
            let _ = handle.join(); // LAW10: progress ticker panic affects UI cleanup only; scan findings/error result already determined, recall-safe
        }
    }
}

struct CoalescedBatchProducer {
    tx: std::sync::mpsc::SyncSender<Vec<Chunk>>,
    plan: CoalescedPipelinePlan,
    merkle: Option<Arc<keyhog_core::MerkleIndex>>,
    batch: Vec<Chunk>,
    batch_bytes: usize,
    pipeline_alive: bool,
    skipped_unchanged: usize,
}

impl CoalescedBatchProducer {
    fn new(
        tx: std::sync::mpsc::SyncSender<Vec<Chunk>>,
        plan: CoalescedPipelinePlan,
        merkle: Option<Arc<keyhog_core::MerkleIndex>>,
    ) -> Self {
        Self {
            tx,
            plan,
            merkle,
            batch: Vec::with_capacity(plan.batch_chunk_limit),
            batch_bytes: 0,
            pipeline_alive: true,
            skipped_unchanged: 0,
        }
    }

    fn produce_sources(mut self, sources: &[Box<dyn Source>]) -> CoalescedProducerOutcome {
        'sources: for source in sources {
            // Per-source outcome: a source that yields ZERO chunks AND errors
            // failed entirely (e.g. --github-org with a bad token), even if a
            // co-requested source succeeded. Tracked so `run()` can fail closed
            // rather than report "clean" off another source's data.
            let mut src_chunks = 0usize;
            let mut src_errored = false;
            for chunk_result in source.chunks() {
                let ClassifiedSourceChunk::Scan(c) =
                    classify_source_chunk(chunk_result, &mut src_chunks, &mut src_errored)
                else {
                    continue;
                };
                if self.record_unchanged_chunk(&c) {
                    continue;
                }
                if self.should_flush_before(&c) {
                    self.flush_batch();
                    if !self.pipeline_alive {
                        break 'sources;
                    }
                }
                self.push_chunk(c);
                if self.should_flush() {
                    self.flush_batch();
                    if !self.pipeline_alive {
                        break 'sources;
                    }
                }
            }
            // Autoroute evidence is keyed by source family and size
            // provenance. Never let a tail batch from one source absorb the
            // first chunks of the next source: installers calibrate each
            // source workload independently, and a synthetic mixed-family key
            // has no corresponding proof.
            self.flush_batch();
            if !self.pipeline_alive {
                break 'sources;
            }
            finalize_source_outcome(src_chunks, src_errored);
            self.skipped_unchanged += filesystem_source_skipped_unchanged(source.as_ref());
        }

        self.flush_batch();
        CoalescedProducerOutcome {
            skipped_unchanged: self.skipped_unchanged,
        }
    }

    fn record_unchanged_chunk(&mut self, c: &Chunk) -> bool {
        let Some(idx) = self.merkle.as_ref() else {
            return false;
        };
        let Some(path_str) = c.metadata.path.as_deref() else {
            return false;
        };
        let unchanged = idx.record_chunk_path_at_offset_and_check_unchanged(
            std::path::Path::new(path_str),
            c.metadata.base_offset as u64,
            c.metadata.mtime_ns.unwrap_or(0), // LAW10: empty/absent => documented numeric default, recall-safe
            c.metadata.size_bytes.unwrap_or(0), // LAW10: empty/absent => documented numeric default, recall-safe
            c.data.as_bytes(),
        );
        if unchanged {
            self.skipped_unchanged += 1;
        }
        unchanged
    }

    fn push_chunk(&mut self, c: Chunk) {
        if !self.batch.is_empty() {
            self.batch_bytes = self.batch_bytes.saturating_add(1);
        }
        self.batch_bytes = self.batch_bytes.saturating_add(c.data.len());
        self.batch.push(c);
        crate::TOTAL_CHUNKS.fetch_add(1, Ordering::Relaxed);
    }

    fn should_flush_before(&self, next: &Chunk) -> bool {
        if self.batch.is_empty() {
            return false;
        }
        let next_coalesced_bytes = self
            .batch_bytes
            .checked_add(1)
            .and_then(|bytes| bytes.checked_add(next.data.len()));
        self.batch.len() >= self.plan.batch_chunk_limit
            || next_coalesced_bytes.is_none_or(|bytes| bytes > self.plan.batch_bytes_budget)
    }

    fn should_flush(&self) -> bool {
        self.batch.len() >= self.plan.batch_chunk_limit
            || self.batch_bytes >= self.plan.batch_bytes_budget
    }

    fn flush_batch(&mut self) {
        if !self.pipeline_alive || self.batch.is_empty() {
            self.batch.clear();
            self.batch_bytes = 0;
            return;
        }
        let payload = std::mem::take(&mut self.batch);
        self.batch_bytes = 0;
        if self.tx.send(payload).is_err() {
            self.pipeline_alive = false;
        }
    }
}

fn join_coalesced_scanner_thread(
    scanner_thread: std::thread::JoinHandle<
        std::result::Result<Vec<RawMatch>, AutorouteRoutingError>,
    >,
    progress: CoalescedProgressTicker,
) -> Result<Vec<RawMatch>> {
    let findings = match scanner_thread.join() {
        Ok(Ok(findings)) => Ok(findings),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => {
            drop(error);
            tracing::error!("scanner thread panicked mid-scan; results are incomplete");
            let _receipt = crate::record_scanner_panic();
            Err(anyhow::anyhow!(
                "scanner thread panicked mid-scan; results are incomplete"
            ))
        }
    };
    progress.stop();
    findings
}

impl ScanOrchestrator {
    fn coalesced_scanner_worker(&self, scanner: Arc<CompiledScanner>) -> CoalescedScannerWorker {
        let perf_trace = self.effective_config.scanner.perf_trace;
        if let Some(backend) = self.effective_config.backend_override {
            return CoalescedScannerWorker::explicit(scanner, backend, perf_trace);
        }

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
        let router_config = CoalescedMeasuredRouterConfig {
            hw_caps,
            pattern_count,
            rules_digest,
            config_digest,
            autoroute_gpu: self.effective_config.autoroute_gpu,
            autoroute_calibration: self.effective_config.autoroute_calibration,
            autoroute_cache_path,
        };
        CoalescedScannerWorker::measured(scanner, router_config, perf_trace)
    }

    pub(crate) fn scan_sources(
        &self,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::MerkleIndex>>,
        incremental_path: Option<std::path::PathBuf>,
    ) -> Result<Vec<RawMatch>> {
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

        let progress = CoalescedProgressTicker::spawn(show_progress && !self.args.stream);

        // Bytes budget per coalesced batch. Sized to match the
        // engine's `gpu_batch_input_limit()` so one coalesced batch never
        // exceeds the live GPU region-presence input contract. The engine
        // sizes its cap by
        // VRAM (1 GiB on RTX 4090/5090, 128 MiB when VRAM is low or
        // unknown), so the orchestrator inherits that scaling automatically.
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
        // to `batch_bytes_budget` (128 MiB on low/unknown VRAM hosts,
        // up to 1 GiB on big-VRAM cards) of coalesced chunks, so the worst-case
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

        let scanner_worker = self.coalesced_scanner_worker(scanner);
        let scanner_thread = std::thread::spawn(move || scanner_worker.run(rx));

        let producer_outcome = CoalescedBatchProducer::new(tx, pipeline_plan, merkle.clone())
            .produce_sources(&sources);
        let findings = join_coalesced_scanner_thread(scanner_thread, progress)?;

        self.finalize_incremental(
            merkle.as_ref(),
            incremental_path.as_deref(),
            producer_outcome.skipped_unchanged,
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

#[cfg(test)]
mod tests;
