//! Mass scan sessions, text/batch dispatch helpers, scan target resolution, and file descriptor pinning.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use anyhow::{Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use tokio::sync::{mpsc, OwnedMutexGuard};
use crate::daemon::frame;
use crate::daemon::protocol::{
    BackendRecoveryStatus, MassScanStats, RecoveredInputRangeStatus, RequestProfile, Response,
    SourceCoverageGaps, MASS_BATCH_BYTES, MASS_BATCH_CHUNKS,
};
use super::{
    daemon_scan_path_chunks, send_response, MassFilesystemMessage, RequestProfileCapture,
    ServerState,
};

pub(super) struct MassIncrementalState {
    pub(super) index: Arc<keyhog_core::MerkleIndex>,
    pub(super) path: PathBuf,
}

pub(super) struct MassSession {
    pub(super) state: Arc<ServerState>,
    pub(super) dogfood: bool,
    pub(super) profile: bool,
    pub(super) stats: MassScanStats,
    pub(super) started_at: Instant,
    pub(super) filesystem_batches: Option<mpsc::Receiver<MassFilesystemMessage>>,
    pub(super) incremental: Option<MassIncrementalState>,
    pub(super) incremental_requested: Option<bool>,
    pub(super) finding_paths: std::collections::HashSet<PathBuf>,
    pub(super) pathless_findings: usize,
    pub(super) incremental_unpublishable: bool,
    pub(super) _fragment_guard: OwnedMutexGuard<()>,
}

impl MassSession {
    pub(super) fn record(&mut self, batch: &MassBatchDispatch) {
        if !matches!(batch.response, Response::ScanResults { .. }) {
            self.incremental_unpublishable = true;
            return;
        }
        self.stats.batches = self.stats.batches.saturating_add(1);
        self.stats.chunks = self.stats.chunks.saturating_add(batch.chunks);
        self.stats.bytes = self.stats.bytes.saturating_add(batch.bytes);
        if batch.gpu {
            self.stats.gpu_batches = self.stats.gpu_batches.saturating_add(1);
            self.stats.gpu_chunks = self.stats.gpu_chunks.saturating_add(batch.chunks);
            self.stats.gpu_bytes = self.stats.gpu_bytes.saturating_add(batch.bytes);
        }
        self.finding_paths
            .extend(batch.finding_paths.iter().cloned());
        self.pathless_findings = self
            .pathless_findings
            .saturating_add(batch.pathless_findings);
    }

    pub(super) fn incremental_index(
        &mut self,
        configured_path: Option<String>,
    ) -> std::result::Result<Option<Arc<keyhog_core::MerkleIndex>>, String> {
        let requested = configured_path.is_some();
        match self.incremental_requested {
            Some(previous) if previous != requested => {
                return Err(
                    "daemon: one mass transaction cannot mix incremental and non-incremental filesystem roots"
                        .to_string(),
                );
            }
            None => self.incremental_requested = Some(requested),
            Some(_) => {}
        }
        let Some(configured_path) = configured_path else {
            return Ok(None);
        };
        let path = PathBuf::from(configured_path);
        if !path.is_absolute() {
            return Err(
                "daemon: MassFilesystemBegin incremental cache path must be absolute".to_string(),
            );
        }
        if let Some(incremental) = self.incremental.as_ref() {
            if incremental.path != path {
                return Err(
                    "daemon: one mass transaction cannot mix incremental cache paths".to_string(),
                );
            }
            return Ok(Some(incremental.index.clone()));
        }
        let report =
            keyhog_core::MerkleIndex::load_with_spec_report(&path, &self.state.detector_spec_hash);
        if let Some(warning) = crate::orchestrator::incremental_cache_warning(report.status()) {
            tracing::warn!("{warning}");
        }
        let index = Arc::new(report.into_index());
        self.incremental = Some(MassIncrementalState {
            index: index.clone(),
            path,
        });
        Ok(Some(index))
    }

    fn persist_incremental(&self) -> std::io::Result<()> {
        let Some(incremental) = self.incremental.as_ref() else {
            return Ok(());
        };
        if self.incremental_unpublishable {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mass acquisition or scanning failed; refusing to publish an incremental cache",
            ));
        }
        if self.pathless_findings > 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "{} finding(s) had no file path; refusing to publish an incremental cache",
                    self.pathless_findings
                ),
            ));
        }
        for path in &self.finding_paths {
            incremental.index.forget(path);
        }
        incremental
            .index
            .save_with_spec(&incremental.path, &self.state.detector_spec_hash)
    }

    pub(super) fn finish_stats(&self) -> MassScanStats {
        MassScanStats {
            duration_ms: self
                .started_at
                .elapsed()
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
            ..self.stats
        }
    }
}

impl Drop for MassSession {
    fn drop(&mut self) {
        self.state.scanner.clear_fragment_cache();
        self.state.finish_scan();
    }
}

pub(super) async fn stream_mass_filesystem(
    state: &ServerState,
    session: Option<&mut MassSession>,
    transport: &mut frame::ServerTransport,
) -> Result<()> {
    let Some(session) = session else {
        return send_response(
            transport,
            Response::Error {
                message: "daemon: MassFilesystemDrain requires an active MassBegin transaction"
                    .to_string(),
            },
        )
        .await;
    };
    if session.filesystem_batches.is_none() {
        return send_response(
            transport,
            Response::Error {
                message:
                    "daemon: MassFilesystemDrain requires an active daemon-local filesystem source"
                        .to_string(),
            },
        )
        .await;
    }

    loop {
        let message = match session.filesystem_batches.as_mut() {
            Some(receiver) => receiver.recv().await,
            None => {
                return send_response(
                    transport,
                    Response::Error {
                        message:
                            "daemon: local filesystem source ended before its terminal response"
                                .to_string(),
                    },
                )
                .await;
            }
        };
        let response = match message {
            Some(MassFilesystemMessage::Batch(chunks)) => {
                let batch = scan_mass_batch(state, chunks, session.dogfood, session.profile).await;
                session.record(&batch);
                batch.response
            }
            Some(MassFilesystemMessage::Complete {
                source_coverage_gaps,
                skipped_unchanged,
            }) => {
                session.filesystem_batches = None;
                if source_coverage_gaps.source_failed > 0 {
                    session.incremental_unpublishable = true;
                }
                match session.persist_incremental() {
                    Ok(()) => Response::MassFilesystemComplete {
                        source_coverage_gaps,
                        skipped_unchanged,
                    },
                    Err(error) => Response::MassFilesystemIncrementalError {
                        message: format!("daemon: cannot persist mass incremental cache: {error}"),
                    },
                }
            }
            None => {
                session.incremental_unpublishable = true;
                session.filesystem_batches = None;
                Response::Error {
                    message: "daemon: local filesystem producer ended without a completion receipt"
                        .to_string(),
                }
            }
        };
        let terminal = !matches!(response, Response::ScanResults { .. });
        if terminal {
            session.filesystem_batches = None;
        }
        send_response(transport, response).await?;
        if terminal {
            return Ok(());
        }
    }
}


pub(super) async fn scan_text(
    state: &ServerState,
    path: Option<String>,
    text: String,
    dogfood: bool,
    profile: bool,
) -> Response {
    state.begin_scan();
    let scanner = state.scanner.clone();
    let router = state.router.clone();
    let backend_override = state.backend_override;
    let recover_automatic_backend_faults = crate::orchestrator::automatic_backend_recovery_allowed(
        backend_override,
        false,
        keyhog_scanner::gpu::gpu_runtime_policy(),
    );
    let fragment_scan_lock = state.fragment_scan_lock.clone();
    let chunk_path = path.clone();
    let telemetry = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
    if dogfood {
        telemetry.enable_dogfood();
    }
    let profile_capture =
        profile.then(|| RequestProfileCapture::new(state.request_identity.next()));
    let _fragment_guard = fragment_scan_lock.lock_owned().await;
    scanner.clear_fragment_cache();
    // Hand the actual scan to a blocking thread - calibrated backend scanning
    // is CPU-heavy and not async-aware. Without `spawn_blocking` a
    // large scan would stall the tokio reactor and block every
    // other connection's framing reads.
    let res = tokio::task::spawn_blocking(move || -> Result<_> {
        let _profile_guard = profile_capture.as_ref().map(RequestProfileCapture::enter);
        let profile_started = Instant::now();
        let (matches, backend_recovery) = keyhog_scanner::telemetry::with_scan_telemetry(
            &telemetry,
            || -> Result<(Vec<RawMatch>, Option<BackendRecoveryStatus>)> {
                scanner.clear_fragment_cache();
                // ScanText constructs its chunk without a source adapter, so
                // the daemon request is the acquisition boundary for input
                // accounting.
                keyhog_profile::add_input_units(1);
                keyhog_profile::add_input_bytes(text.len() as u64);
                let chunk = Chunk {
                    data: text.into(),
                    metadata: ChunkMetadata {
                        source_type: "stdin".into(),
                        path: chunk_path.map(Into::into),
                        ..Default::default()
                    },
                };
                if chunk.data.is_empty() {
                    scanner.clear_fragment_cache();
                    return Ok((Vec::new(), None));
                }
                let selection = router.choose_with_plan(
                    scanner.as_ref(),
                    backend_override,
                    std::slice::from_ref(&chunk),
                )?;
                let batch = std::slice::from_ref(&chunk);
                let outcome = crate::orchestrator::scan_selected_batch(
                    scanner.as_ref(),
                    batch,
                    selection.backend,
                    #[cfg(feature = "gpu")]
                    selection.ordered_gpu.as_deref(),
                    selection.phase1_plan.as_ref(),
                    selection.execution_route,
                    selection
                        .recovery_plan
                        .filter(|_| recover_automatic_backend_faults),
                )
                .with_context(|| {
                    format!(
                        "selected backend {} failed during daemon text dispatch",
                        selection.backend.label()
                    )
                })?;
                if let Some(recovery) = outcome.recovery.as_ref() {
                    router.quarantine_recovered_route(&selection, recovery)?;
                }
                let backend_recovery = outcome
                    .recovery
                    .as_ref()
                    .map(backend_recovery_status_from_receipt);
                scanner.clear_fragment_cache();
                Ok((
                    outcome.per_chunk.into_iter().flatten().collect(),
                    backend_recovery,
                ))
            },
        )?;
        let telemetry = telemetry.drain();
        let profile = profile_capture.map(|capture| capture.finish(profile_started));
        Ok((matches, telemetry, backend_recovery, profile))
    })
    .await;
    state.finish_scan();
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok(Ok((matches, telemetry, backend_recovery, profile))) => {
            if let Some(recovery) = backend_recovery.clone() {
                if let Err(error) = state.record_backend_recovery(recovery) {
                    return Response::Error {
                        message: format!(
                            "daemon: scan recovered, but health recording failed: {error:#}"
                        ),
                    };
                }
            }
            scan_results_response(
                path,
                matches,
                telemetry,
                SourceCoverageGaps::default(),
                backend_recovery,
                profile,
            )
        }
        Ok(Err(e)) => Response::Error {
            message: format!("daemon: scan_text failed: {e:#}"),
        },
        Err(e) => Response::Error {
            message: format!("daemon: scan task panicked or was cancelled: {e:#}"),
        },
    }
}

/// Resolve the path a client asked the daemon to scan into the path the scanner
/// will open. Absolute paths pass through; a relative path is anchored to the
/// client's absolute `working_dir`; a relative path with no usable working dir
/// returns an error to the client before any path is scanned. The client sends
/// `working_dir=None` only when its own `std::env::current_dir()` failed (see
/// subcommands/scan.rs); using the unrelated daemon cwd would scan the wrong
/// tree, so this path fails closed and surfaces the resolution error.
pub(crate) fn resolve_scan_target(
    path: &str,
    working_dir: Option<&str>,
) -> Result<PathBuf, String> {
    if Path::new(path).is_absolute() {
        Ok(PathBuf::from(path))
    } else if let Some(wd) = working_dir {
        let working_dir = Path::new(wd);
        if !working_dir.is_absolute() {
            return Err(format!(
                "daemon: cannot resolve relative path {path:?} - working_dir {wd:?} is not absolute. \
                 Resend the request with an absolute path or absolute working_dir."
            ));
        }
        let resolved = working_dir.join(path);
        if !resolved.is_absolute() {
            return Err(format!(
                "daemon: cannot resolve relative path {path:?} - resolved target {resolved:?} is \
                 not absolute. Resend the request with a fully absolute path."
            ));
        }
        Ok(resolved)
    } else {
        Err(format!(
            "daemon: cannot resolve relative path {path:?} - no working_dir was provided (the client \
             could not determine its current directory). Resend the request with an absolute path."
        ))
    }
}

pub(super) async fn scan_path(
    state: &ServerState,
    path: String,
    working_dir: Option<String>,
    dogfood: bool,
    profile: bool,
) -> Response {
    let resolved = match resolve_scan_target(&path, working_dir.as_deref()) {
        Ok(target) => target,
        Err(message) => return Response::Error { message },
    };
    // The client validates that its argument is a regular file, but the server
    // used to reopen only the pathname, so a directory, FIFO, socket, or symlink
    // swapped in afterwards was scanned instead. Pin the identity here: the
    // handle stays open across the scan and its inode is re-checked afterwards,
    // so a replacement race fails closed instead of returning findings from
    // substituted content (KH-553).
    let pinned = match pin_regular_file(&resolved) {
        Ok(pinned) => pinned,
        Err(message) => return Response::Error { message },
    };

    state.begin_scan();
    let scanner = state.scanner.clone();
    let router = state.router.clone();
    let backend_override = state.backend_override;
    let recover_automatic_backend_faults = crate::orchestrator::automatic_backend_recovery_allowed(
        backend_override,
        false,
        keyhog_scanner::gpu::gpu_runtime_policy(),
    );
    let fragment_scan_lock = state.fragment_scan_lock.clone();
    let resolved_owned = resolved.clone();
    let telemetry = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
    let source_telemetry = Arc::new(keyhog_sources::SourceSkipTelemetry::new());
    if dogfood {
        telemetry.enable_dogfood();
    }
    let profile_capture =
        profile.then(|| RequestProfileCapture::new(state.request_identity.next()));
    let _fragment_guard = fragment_scan_lock.lock_owned().await;
    scanner.clear_fragment_cache();
    type ScanOutput = (
        Vec<RawMatch>,
        keyhog_scanner::telemetry::ScanTelemetrySnapshot,
        SourceCoverageGaps,
        Option<BackendRecoveryStatus>,
        Option<RequestProfile>,
    );
    let res = tokio::task::spawn_blocking(move || -> Result<ScanOutput> {
        let _profile_guard = profile_capture.as_ref().map(RequestProfileCapture::enter);
        let profile_started = Instant::now();
        let scanned = (|| -> Result<
            (
                Vec<RawMatch>,
                keyhog_scanner::telemetry::ScanTelemetrySnapshot,
                SourceCoverageGaps,
                Option<BackendRecoveryStatus>,
            ),
        > {
            let (chunks, source_coverage_gaps) =
                daemon_scan_path_chunks(&resolved_owned, &source_telemetry)?;
            pinned.verify_unreplaced(&resolved_owned)?;
            if chunks.iter().all(|chunk| chunk.data.is_empty()) {
                return Ok((Vec::new(), telemetry.drain(), source_coverage_gaps, None));
            }
            let (matches, backend_recovery) = keyhog_scanner::telemetry::with_scan_telemetry(
                &telemetry,
                || -> Result<(Vec<RawMatch>, Option<BackendRecoveryStatus>)> {
                let selection =
                    router.choose_with_plan(scanner.as_ref(), backend_override, &chunks)?;
                let outcome = crate::orchestrator::scan_selected_batch(
                    scanner.as_ref(),
                    &chunks,
                    selection.backend,
                    #[cfg(feature = "gpu")]
                    selection.ordered_gpu.as_deref(),
                    selection.phase1_plan.as_ref(),
                    selection.execution_route,
                    selection
                        .recovery_plan
                        .filter(|_| recover_automatic_backend_faults),
                )
                .with_context(|| {
                    format!(
                        "selected backend {} failed during daemon dispatch",
                        selection.backend.label()
                    )
                })?;
                if let Some(recovery) = outcome.recovery.as_ref() {
                    router.quarantine_recovered_route(&selection, recovery)?;
                }
                let backend_recovery = outcome
                    .recovery
                    .as_ref()
                    .map(backend_recovery_status_from_receipt);
                scanner.clear_fragment_cache();
                let mut per_chunk = outcome.per_chunk;
                crate::inline_suppression::attach_inline_suppression_context(
                    &chunks,
                    &mut per_chunk,
                );
                Ok((per_chunk.into_iter().flatten().collect(), backend_recovery))
            },
        )?;
            Ok((
                matches,
                telemetry.drain(),
                source_coverage_gaps,
                backend_recovery,
            ))
        })();
        let (matches, telemetry, source_coverage_gaps, backend_recovery) = scanned?;
        let profile = profile_capture.map(|capture| capture.finish(profile_started));
        Ok((
            matches,
            telemetry,
            source_coverage_gaps,
            backend_recovery,
            profile,
        ))
    })
    .await;
    state.finish_scan();
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok(Ok((matches, telemetry, source_coverage_gaps, backend_recovery, profile))) => {
            if let Some(recovery) = backend_recovery.clone() {
                if let Err(error) = state.record_backend_recovery(recovery) {
                    return Response::Error {
                        message: format!(
                            "daemon: scan recovered, but health recording failed: {error:#}"
                        ),
                    };
                }
            }
            scan_results_response(
                Some(resolved.to_string_lossy().into_owned()),
                matches,
                telemetry,
                source_coverage_gaps,
                backend_recovery,
                profile,
            )
        }
        Ok(Err(e)) => Response::Error {
            message: format!("daemon: scan_path failed: {e:#}"),
        },
        Err(e) => Response::Error {
            message: format!("daemon: scan task panicked or was cancelled: {e:#}"),
        },
    }
}

pub(super) struct MassBatchDispatch {
    pub(super) response: Response,
    pub(super) chunks: u64,
    pub(super) bytes: u64,
    pub(super) gpu: bool,
    pub(super) finding_paths: Vec<PathBuf>,
    pub(super) pathless_findings: usize,
}

impl MassBatchDispatch {
    pub(super) fn error(message: String) -> Self {
        Self {
            response: Response::Error { message },
            chunks: 0,
            bytes: 0,
            gpu: false,
            finding_paths: Vec::new(),
            pathless_findings: 0,
        }
    }
}

pub(super) fn validate_mass_batch(chunks: &[Chunk]) -> std::result::Result<(u64, usize), String> {
    if chunks.is_empty() {
        return Err("daemon: MassBatch must contain at least one chunk".to_string());
    }
    if chunks.len() > MASS_BATCH_CHUNKS {
        return Err(format!(
            "daemon: MassBatch contains {} chunks; maximum is {MASS_BATCH_CHUNKS}",
            chunks.len()
        ));
    }
    let batch_bytes = chunks
        .iter()
        .try_fold(0usize, |total, chunk| total.checked_add(chunk.data.len()))
        .ok_or_else(|| "daemon: MassBatch byte count overflow".to_string())?;
    if batch_bytes > MASS_BATCH_BYTES {
        return Err(format!(
            "daemon: MassBatch contains {batch_bytes} raw bytes; maximum is {MASS_BATCH_BYTES}"
        ));
    }
    Ok((chunks.len() as u64, batch_bytes))
}

pub(super) async fn scan_mass_batch(
    state: &ServerState,
    chunks: Vec<Chunk>,
    dogfood: bool,
    profile: bool,
) -> MassBatchDispatch {
    let (chunk_count, batch_bytes) = match validate_mass_batch(&chunks) {
        Ok(shape) => shape,
        Err(message) => return MassBatchDispatch::error(message),
    };

    let scanner = state.scanner.clone();
    let router = state.router.clone();
    let backend_override = state.backend_override;
    let recover_automatic_backend_faults = crate::orchestrator::automatic_backend_recovery_allowed(
        backend_override,
        false,
        keyhog_scanner::gpu::gpu_runtime_policy(),
    );
    let telemetry = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
    if dogfood {
        telemetry.enable_dogfood();
    }
    let profile_capture =
        profile.then(|| RequestProfileCapture::new(state.request_identity.next()));
    let res = tokio::task::spawn_blocking(move || -> Result<_> {
        let _profile_guard = profile_capture.as_ref().map(RequestProfileCapture::enter);
        let profile_started = Instant::now();
        let scanned = (|| -> Result<_> {
            // Mass batches arrive from the client without a daemon-side source
            // adapter, so the request is the acquisition boundary for input
            // accounting.
            keyhog_profile::add_input_units(chunk_count);
            keyhog_profile::add_input_bytes(batch_bytes as u64);
            if chunks.iter().all(|chunk| chunk.data.is_empty()) {
                return Ok((Vec::new(), telemetry.drain(), None, false));
            }
            let (matches, backend_recovery, gpu) = keyhog_scanner::telemetry::with_scan_telemetry(
                &telemetry,
                || -> Result<(Vec<RawMatch>, Option<BackendRecoveryStatus>, bool)> {
                    let selection =
                        router.choose_with_plan(scanner.as_ref(), backend_override, &chunks)?;
                    let outcome = crate::orchestrator::scan_selected_batch(
                        scanner.as_ref(),
                        &chunks,
                        selection.backend,
                        #[cfg(feature = "gpu")]
                        selection.ordered_gpu.as_deref(),
                        selection.phase1_plan.as_ref(),
                        selection.execution_route,
                        selection
                            .recovery_plan
                            .filter(|_| recover_automatic_backend_faults),
                    )
                    .with_context(|| {
                        format!(
                            "selected backend {} failed during mass daemon dispatch",
                            selection.backend.label()
                        )
                    })?;
                    if let Some(recovery) = outcome.recovery.as_ref() {
                        router.quarantine_recovered_route(&selection, recovery)?;
                    }
                    let backend_recovery = outcome
                        .recovery
                        .as_ref()
                        .map(backend_recovery_status_from_receipt);
                    let gpu = selection.backend.is_gpu() && !outcome.recovered;
                    let mut per_chunk = outcome.per_chunk;
                    crate::inline_suppression::attach_inline_suppression_context(
                        &chunks,
                        &mut per_chunk,
                    );
                    Ok((
                        per_chunk.into_iter().flatten().collect(),
                        backend_recovery,
                        gpu,
                    ))
                },
            )?;
            Ok((matches, telemetry.drain(), backend_recovery, gpu))
        })();
        let (matches, telemetry, backend_recovery, gpu) = scanned?;
        let profile = profile_capture.map(|capture| capture.finish(profile_started));
        Ok((matches, telemetry, backend_recovery, gpu, profile))
    })
    .await;

    match res {
        Ok(Ok((matches, telemetry, backend_recovery, gpu, profile))) => {
            if let Some(recovery) = backend_recovery.clone() {
                if let Err(error) = state.record_backend_recovery(recovery) {
                    return MassBatchDispatch::error(format!(
                        "daemon: mass batch recovered, but health recording failed: {error:#}"
                    ));
                }
            }
            let mut pathless_findings = 0usize;
            let finding_paths = matches
                .iter()
                .filter_map(|finding| match finding.location.file_path.as_deref() {
                    Some(path) => Some(PathBuf::from(path)),
                    None => {
                        pathless_findings = pathless_findings.saturating_add(1);
                        None
                    }
                })
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect();
            MassBatchDispatch {
                response: scan_results_response(
                    None,
                    matches,
                    telemetry,
                    SourceCoverageGaps::default(),
                    backend_recovery,
                    profile,
                ),
                chunks: chunk_count,
                bytes: batch_bytes as u64,
                gpu,
                finding_paths,
                pathless_findings,
            }
        }
        Ok(Err(error)) => MassBatchDispatch::error(format!("daemon: mass batch failed: {error:#}")),
        Err(error) => MassBatchDispatch::error(format!(
            "daemon: mass batch task panicked or was cancelled: {error:#}"
        )),
    }
}

pub(super) fn scan_results_response(
    path: Option<String>,
    matches: Vec<RawMatch>,
    telemetry: keyhog_scanner::telemetry::ScanTelemetrySnapshot,
    source_coverage_gaps: SourceCoverageGaps,
    backend_recovery: Option<BackendRecoveryStatus>,
    profile: Option<RequestProfile>,
) -> Response {
    Response::ScanResults {
        path,
        matches,
        engine_example_suppressions: telemetry.example_suppressions,
        dogfood_events: telemetry.dogfood_events,
        static_recovery_rejections: telemetry.static_recovery_rejections,
        static_recovery_status: telemetry.static_recovery_status,
        dogfood_detail_events_dropped: telemetry.dogfood_detail_events_dropped,
        source_coverage_gaps,
        backend_recovery: backend_recovery.into(),
        profile: profile.into(),
    }
}

pub(super) fn backend_recovery_status_from_receipt(
    receipt: &keyhog_scanner::BackendRecoveryReceipt,
) -> BackendRecoveryStatus {
    BackendRecoveryStatus {
        failed_backend: receipt.failed_backend.label().to_string(),
        recovery_backend: receipt.recovery_backend.label().to_string(),
        recovered_ranges: receipt
            .ranges
            .iter()
            .map(|range| RecoveredInputRangeStatus {
                chunk_index: range.chunk_index,
                byte_start: range.byte_start,
                byte_end: range.byte_end,
            })
            .collect(),
        recovered_chunks: receipt.recovered_chunks(),
        recovered_bytes: receipt.recovered_bytes(),
        reason: receipt.reason.clone(),
    }
}

/// An open, no-follow handle to the exact regular file one `ScanPath` request
/// named. Held for the whole scan so the inode cannot be recycled underneath the
/// read, and re-checked afterwards against the pathname.
#[derive(Debug)]
pub(super) struct PinnedFile(pub(super) std::fs::File);

/// Open `path` without following a final symlink and require a regular file.
///
/// `ScanPath` is documented as a regular-file request and the client checks that
/// before sending, but the server is the side that must enforce it: without this
/// a directory argument makes the daemon walk and scan an entire tree while
/// holding the fragment lease, and a FIFO or socket argument turns a scan into an
/// open on a file type the source layer never promised to handle.
pub(super) fn pin_regular_file(path: &Path) -> std::result::Result<PinnedFile, String> {
    use std::os::unix::fs::OpenOptionsExt;
    // Classify without following, so the refusal can name what the path actually
    // is. `O_NOFOLLOW` below would report a symlink as `ELOOP`, which tells the
    // operator nothing about why their argument was rejected.
    let requested = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "daemon: cannot identify scan target {}: {error}",
            path.display()
        )
    })?;
    if !requested.file_type().is_file() {
        return Err(refused_file_type_message(path, &requested.file_type()));
    }
    // O_NOFOLLOW rejects a symlinked final component instead of resolving it, so
    // a symlink swapped in after the classification above cannot be opened.
    // O_NONBLOCK keeps a FIFO from parking the open before the type check runs.
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            format!(
                "daemon: cannot open scan target {}: {error}",
                path.display()
            )
        })?;
    let metadata = handle.metadata().map_err(|error| {
        format!(
            "daemon: cannot identify scan target {}: {error}",
            path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(refused_file_type_message(path, &metadata.file_type()));
    }
    Ok(PinnedFile(handle))
}

pub(super) fn refused_file_type_message(path: &Path, file_type: &std::fs::FileType) -> String {
    format!(
        "daemon: refusing to scan {}: ScanPath serves regular files only and this path is {}. \
         Scan a directory in process with `--daemon=off`, or as bounded batches with \
         `--daemon=mass`.",
        path.display(),
        file_type_label(file_type)
    )
}

impl PinnedFile {
    /// Fail closed when `path` no longer names the inode this request pinned.
    /// The open handle keeps that inode alive, so an inode difference here means
    /// the pathname was rebound to different content during the scan.
    fn verify_unreplaced(&self, path: &Path) -> Result<()> {
        let pinned = self.0.metadata().with_context(|| {
            format!("daemon: re-identify pinned scan target {}", path.display())
        })?;
        let current = std::fs::symlink_metadata(path).with_context(|| {
            format!(
                "daemon: re-identify scan target path {} after reading it",
                path.display()
            )
        })?;
        if current.dev() != pinned.dev() || current.ino() != pinned.ino() {
            anyhow::bail!(
                "daemon: {} was replaced while it was being scanned (pinned inode {}:{}, now \
                 {}:{}); refusing to report findings for substituted content",
                path.display(),
                pinned.dev(),
                pinned.ino(),
                current.dev(),
                current.ino()
            );
        }
        Ok(())
    }
}

pub(super) fn file_type_label(file_type: &std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    if file_type.is_dir() {
        "a directory"
    } else if file_type.is_symlink() {
        "a symbolic link"
    } else if file_type.is_fifo() {
        "a FIFO"
    } else if file_type.is_socket() {
        "a socket"
    } else if file_type.is_block_device() {
        "a block device"
    } else if file_type.is_char_device() {
        "a character device"
    } else {
        "not a regular file"
    }
}

