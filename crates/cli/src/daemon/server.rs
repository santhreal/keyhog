//! Daemon server: long-lived process that holds a compiled scanner
//! and serves scan requests over a Unix socket.

use crate::daemon::frame;
use crate::daemon::protocol::{
    BackendRecoveryStatus, MassScanStats, RecoveredInputRangeStatus, Request, Response,
    SourceCoverageGaps, WarmBackendStatus, MASS_BATCH_BYTES, MASS_BATCH_CHUNKS, WIRE_VERSION,
};
use crate::daemon::trust;
use crate::daemon::warm_identity::WarmBackendReadiness;
use crate::style;
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, RawMatch, Source};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::{Path, PathBuf};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex, Notify, OwnedMutexGuard, Semaphore};

const KEYHOG_VERSION: &str = env!("CARGO_PKG_VERSION");
static DAEMON_SOURCE_COVERAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const DEFAULT_REQUEST_READ_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, Copy)]
pub(crate) struct ServerOptions {
    /// Maximum wall-clock time a single client request may take to fully arrive
    /// once the connection is otherwise idle-waiting for it. Bounds a slowloris
    /// / half-frame stall: a peer that announces a frame length (up to the
    /// 64 MiB `MAX_FRAME_BYTES`) then sends the body slowly, or never, would
    /// otherwise hold a `connection_limit` semaphore permit forever.
    pub request_read_timeout: Duration,
    /// Enable the explicit bounded mass-service transaction protocol.
    pub mass_service: bool,
    /// Require a terminal receipt proving GPU processed most mass payload bytes.
    pub mass_gpu_primary_required: bool,
}

/// Fatal terminal outcomes from the running daemon service.
#[derive(Debug)]
pub(crate) enum DaemonServiceFailure {
    AcceptLoopTask(String),
    ListenerAccept(std::io::Error),
    ConnectionHandlerSpawn(String),
}

impl std::fmt::Display for DaemonServiceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AcceptLoopTask(error) => {
                write!(f, "daemon service failed: accept loop task failed: {error}")
            }
            Self::ListenerAccept(error) => {
                write!(
                    f,
                    "daemon service failed: listener accept failed fatally: {error}"
                )
            }
            Self::ConnectionHandlerSpawn(error) => write!(
                f,
                "daemon service failed: connection handler spawn failed: {error}"
            ),
        }
    }
}

impl std::error::Error for DaemonServiceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AcceptLoopTask(_) => None,
            Self::ListenerAccept(error) => Some(error),
            Self::ConnectionHandlerSpawn(_) => None,
        }
    }
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            request_read_timeout: Duration::from_secs(DEFAULT_REQUEST_READ_TIMEOUT_SECS),
            mass_service: false,
            mass_gpu_primary_required: false,
        }
    }
}

/// Default socket path. Prefers `$XDG_RUNTIME_DIR/keyhog.sock` (per-user,
/// tmpfs-backed, auto-cleaned on logout), then the OS user-cache directory,
/// then the OS temporary directory plus `keyhog/server.sock` when neither
/// location is available (for example in minimal containers).
///
/// This is the everyday default. To point a `scan --daemon` at a daemon bound
/// to a non-default path (a `daemon start --socket <path>` daemon, e.g. a
/// systemd unit), pass `scan --daemon-socket <path>`: the blessed CLI override
/// tier. KeyHog deliberately reads no `KEYHOG_*` socket env var (see
/// docs/src/reference/env.md): socket location follows this resolver or a CLI
/// flag; there is no ambient KeyHog-owned socket environment knob.
pub fn default_socket_path() -> PathBuf {
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let mut p = PathBuf::from(runtime_dir);
        p.push("keyhog.sock");
        return p;
    }
    // `dirs::cache_dir()` returns ~/.cache on Linux, ~/Library/Caches on
    // macOS, %LOCALAPPDATA% on Windows. Fall back to the OS temp dir
    // when that lookup fails (e.g. inside a Docker container with no
    // HOME set) - `std::env::temp_dir()` is /tmp on Unix and
    // %TEMP% on Windows, never the hardcoded `/tmp` we used before
    // (which would silently mkdir `C:\tmp` on Windows).
    let cache = dirs::cache_dir().unwrap_or_else(std::env::temp_dir); // LAW10: no parent/unresolved path => '.' (current dir), intended path default; recall-safe
    let mut p = cache;
    p.push("keyhog");
    p.push("server.sock");
    p
}

struct ServerState {
    scanner: Arc<CompiledScanner>,
    router: Arc<crate::orchestrator::CachedBackendRouter>,
    started_at: Instant,
    scans_served: AtomicU64,
    active_scans: AtomicU32,
    shutdown: Arc<Notify>,
    detector_count: usize,
    detector_rules_digest: String,
    request_read_timeout: Duration,
    backend_override: Option<ScanBackend>,
    backend_recoveries: AtomicU64,
    last_backend_fault: std::sync::Mutex<Option<BackendRecoveryStatus>>,
    warm_backend: WarmBackendReadiness,
    mass_service: bool,
    mass_gpu_primary_required: bool,
    // Fragment reassembly is scanner-owned mutable state. A normal request
    // leases it for one scan; a mass connection leases it from MassBegin
    // through MassEnd so batches preserve seam recall without cross-job state.
    fragment_scan_lock: Arc<Mutex<()>>,
    // Caps concurrent in-flight client connections. Without this,
    // every accepted socket spawns an unbounded tokio task that in
    // turn unboundedly spawn_blocks a scanner thread. A burst of
    // 10 000 connections from a misconfigured CI runner would
    // exhaust file descriptors and rayon threads in seconds.
    // Default = 4 × physical cores so a 16-core host serves 64
    // concurrent scans, which is the saturation point for the
    // bounded sync_channel(64) the scanner uses internally.
    connection_limit: Arc<Semaphore>,
}

impl ServerState {
    fn new(
        scanner: Arc<CompiledScanner>,
        router: crate::orchestrator::CachedBackendRouter,
        shutdown: Arc<Notify>,
        detector_count: usize,
        detector_rules_digest: String,
        options: ServerOptions,
        backend_override: Option<ScanBackend>,
        warm_backend: WarmBackendReadiness,
    ) -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4); // LAW10: absent config => documented default; Tier-A knob, recall-irrelevant
        let max_conns = (cores * 4).clamp(8, 256);
        Self {
            scanner,
            router: Arc::new(router),
            started_at: Instant::now(),
            scans_served: AtomicU64::new(0),
            active_scans: AtomicU32::new(0),
            shutdown,
            detector_count,
            detector_rules_digest,
            request_read_timeout: options.request_read_timeout,
            backend_override,
            backend_recoveries: AtomicU64::new(0),
            last_backend_fault: std::sync::Mutex::new(None),
            warm_backend,
            mass_service: options.mass_service,
            mass_gpu_primary_required: options.mass_gpu_primary_required,
            fragment_scan_lock: Arc::new(Mutex::new(())),
            connection_limit: Arc::new(Semaphore::new(max_conns)),
        }
    }

    fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    fn backend_policy(&self) -> &'static str {
        match self.backend_override {
            Some(backend) => backend.label(),
            None if self.router.autoroute_state_is_invalid() => "autoroute-recovery",
            None if self.router.autoroute_has_quarantined_routes() => "autoroute-degraded",
            None => "autoroute",
        }
    }

    fn record_backend_recovery(&self, recovery: BackendRecoveryStatus) -> Result<()> {
        *self
            .last_backend_fault
            .lock()
            .map_err(|_| anyhow::anyhow!("daemon backend-recovery health lock is poisoned"))? =
            Some(recovery);
        self.backend_recoveries.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn warm_backend_status(&self) -> WarmBackendStatus {
        self.warm_backend.status(&self.scanner)
    }
}
pub(crate) fn warm_route_error(status: &WarmBackendStatus) -> Option<Response> {
    if status.ready {
        return None;
    }
    let message = match (
        status.reason.as_deref(),
        status.repair_command.as_deref(),
    ) {
        (Some(reason), Some(repair)) => {
            format!("daemon warm route is not ready: {reason}. Repair with `{repair}`.")
        }
        _ => "daemon warm route is not ready and its exact status is internally inconsistent. Repair with `keyhog daemon stop && keyhog daemon start`.".to_string(),
    };
    Some(Response::Error { message })
}

pub(crate) async fn run_with_backend_override(
    socket_path: PathBuf,
    detectors: Vec<DetectorSpec>,
    options: ServerOptions,
    backend_override: Option<ScanBackend>,
) -> Result<()> {
    // Tell the operator the daemon is working before scanner compile and warmup.
    // Duration varies with the detector corpus, backend, cache state, and host.
    // The count is the pre-compile spec count; the ready line reports the final
    // compiled count.
    announce_daemon_starting(detectors.len());
    let detector_rules_digest =
        keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(&detectors));
    let (scanner, router, detector_count, required_backends) =
        compile_daemon_scan_runtime(detectors, backend_override)?;
    let warm_backend =
        WarmBackendReadiness::capture(&scanner, &detector_rules_digest, required_backends)?;
    let listener = bind_trusted_daemon_socket(&socket_path)?;
    let shutdown = Arc::new(Notify::new());
    let state = Arc::new(ServerState::new(
        scanner,
        router,
        shutdown.clone(),
        detector_count,
        detector_rules_digest,
        options,
        backend_override,
        warm_backend,
    ));

    announce_daemon_ready(&socket_path, detector_count, &state.warm_backend_status());
    let accept_task = spawn_accept_loop(listener, state.clone());

    finish_daemon_service(&socket_path, accept_task).await
}

async fn finish_daemon_service(
    socket_path: &Path,
    accept_task: tokio::task::JoinHandle<std::result::Result<(), DaemonServiceFailure>>,
) -> Result<()> {
    let terminal_outcome: std::result::Result<(), DaemonServiceFailure> = match accept_task.await {
        Ok(inner) => inner,
        Err(join_error) => Err(DaemonServiceFailure::AcceptLoopTask(join_error.to_string())),
    };
    let cleanup = remove_daemon_socket_on_shutdown(socket_path);
    match (terminal_outcome, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error.into()),
        (Err(failure), Ok(())) => Err(anyhow::Error::new(failure)),
        (Err(failure), Err(cleanup_error)) => Err(anyhow::Error::new(failure).context(format!(
            "daemon socket cleanup also failed: {cleanup_error:#}"
        ))),
    }
}

fn compile_daemon_scan_runtime(
    detectors: Vec<DetectorSpec>,
    backend_override: Option<ScanBackend>,
) -> Result<(
    Arc<CompiledScanner>,
    crate::orchestrator::CachedBackendRouter,
    usize,
    Vec<ScanBackend>,
)> {
    let scan_runtime = crate::orchestrator::compile_default_scan_runtime(
        detectors,
        crate::orchestrator::daemon_compile_failure,
    )?
    .prepare_persistent_daemon(backend_override)?;
    let detector_count = scan_runtime.detector_count();
    // The daemon is long-lived and serves many scan requests; pay the lazy
    // regex compile once, up front and in parallel, so no client request eats a
    // detector's first-use compile latency.
    let (scanner, router) = scan_runtime.into_parts();
    let required_backends = match backend_override {
        Some(backend) => vec![backend],
        None => router.persistent_routes().map_err(anyhow::Error::from)?,
    };
    Ok((scanner, router, detector_count, required_backends))
}

fn bind_trusted_daemon_socket(socket_path: &Path) -> Result<UnixListener> {
    if let Some(parent) = socket_path.parent() {
        trust::ensure_private_socket_dir(parent)?;
    }
    // Remove a stale socket file from a previous crashed instance only after the
    // parent dir and stale socket file both pass the daemon trust checks.
    trust::remove_stale_socket_if_trusted(socket_path)?;

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("daemon: binding Unix socket at {}", socket_path.display()))?;

    // 0600 = user-only. Without this the socket inherits the umask default which
    // on most distros is 0644 - a co-tenant user on the same box could connect
    // and request scans, exposing every credential the scanner finds.
    trust::set_socket_mode_user_only(socket_path)?;
    Ok(listener)
}

fn announce_daemon_starting(detector_spec_count: usize) {
    eprintln!(
        "keyhog daemon: compiling {detector_spec_count} detectors \
         (compatible later starts may reuse compiled caches)…"
    );
}

fn announce_daemon_ready(
    socket_path: &Path,
    detector_count: usize,
    warm_backend: &WarmBackendStatus,
) {
    if warm_backend.ready {
        eprintln!(
            "keyhog daemon ready on {} ({} detectors, wire={}, warm generation={})",
            socket_path.display(),
            detector_count,
            WIRE_VERSION,
            warm_backend.daemon_generation,
        );
        return;
    }
    match (
        warm_backend.reason.as_deref(),
        warm_backend.repair_command.as_deref(),
    ) {
        (Some(reason), Some(repair)) => eprintln!(
            "keyhog daemon status-only on {} ({} detectors, wire={}): warm route not ready: {}; repair with `{}`",
            socket_path.display(),
            detector_count,
            WIRE_VERSION,
            reason,
            repair,
        ),
        _ => eprintln!(
            "keyhog daemon status-only on {} ({} detectors, wire={}): warm readiness status is internally inconsistent; repair with `keyhog daemon stop && keyhog daemon start`",
            socket_path.display(),
            detector_count,
            WIRE_VERSION,
        ),
    }
}

fn spawn_accept_loop(
    listener: UnixListener,
    state: Arc<ServerState>,
) -> tokio::task::JoinHandle<std::result::Result<(), DaemonServiceFailure>> {
    tokio::spawn(run_accept_loop(listener, state))
}

async fn run_accept_loop(
    listener: UnixListener,
    state: Arc<ServerState>,
) -> std::result::Result<(), DaemonServiceFailure> {
    loop {
        tokio::select! {
            _ = state.shutdown.notified() => return Ok(()),
            conn = listener.accept() => {
                match conn {
                    Ok((stream, _addr)) => {
                        if let Err(error) = spawn_connection_handler(state.clone(), stream).await {
                            return Err(handle_connection_spawn_error(&state.shutdown, error));
                        }
                    }
                    Err(e) => {
                        handle_accept_error(&state.shutdown, e).await?;
                    }
                }
            }
        }
    }
}

async fn spawn_connection_handler(
    state: Arc<ServerState>,
    stream: UnixStream,
) -> std::result::Result<(), String> {
    let limiter = state.connection_limit.clone();
    // Backpressure: refuse to spawn another handler until a permit is available.
    // A permit drop at the end of the spawned task releases the slot.
    let permit = limiter
        .acquire_owned()
        .await
        .map_err(|error| format!("connection limiter closed: {error}"))?;
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = handle_connection(state, stream).await {
            tracing::warn!("daemon: connection ended with error: {e:#}");
        }
    });
    Ok(())
}

fn handle_connection_spawn_error(shutdown: &Notify, error: String) -> DaemonServiceFailure {
    let palette = style::for_stderr();
    eprintln!(
        "{} keyhog daemon: failed to spawn a connection handler ({error}); \
         the daemon can no longer accept connections and is shutting down. \
         Restart it with `keyhog daemon start`.",
        style::fail("FAIL", &palette)
    );
    shutdown.notify_waiters();
    DaemonServiceFailure::ConnectionHandlerSpawn(error)
}

async fn handle_accept_error(
    shutdown: &Notify,
    error: std::io::Error,
) -> std::result::Result<(), DaemonServiceFailure> {
    // Law 10: a swallowed accept() error silently kills the daemon's ability to
    // serve while the process stays alive. Surface it loudly and either recover
    // from transient bursts or notify shutdown for fatal listener failure.
    if is_transient_accept_error(&error) {
        let palette = style::for_stderr();
        eprintln!(
            "{} keyhog daemon: accept() failed transiently ({error}); \
             backing off and continuing to serve",
            style::warn("WARN", &palette)
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        return Ok(());
    }

    let palette = style::for_stderr();
    eprintln!(
        "{} keyhog daemon: listener accept failed fatally ({error}); \
         the daemon can no longer accept connections and is \
         shutting down. Restart it with `keyhog daemon start`.",
        style::fail("FAIL", &palette)
    );
    shutdown.notify_waiters();
    Err(DaemonServiceFailure::ListenerAccept(error))
}

fn remove_daemon_socket_on_shutdown(socket_path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(socket_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!(
                "daemon: remove socket {} during shutdown",
                socket_path.display()
            )
        }),
    }
}

/// Classify an `accept()` I/O error as transient (recoverable, back off and
/// keep serving) versus fatal (the listening socket is unusable (shut down)).
///
/// Transient cases are the ones a momentary spike produces and that clear on
/// their own once the backlog drains: per-process / system-wide fd exhaustion
/// (`EMFILE` / `ENFILE`, surfaced by std as `Other`), a connection the peer
/// aborted between the SYN and our accept (`ECONNABORTED`), an interrupted
/// syscall (`EINTR` -> `Interrupted`), and a transient resource shortage
/// (`WouldBlock`). Everything else (e.g. the socket fd closed under us) is
/// treated as fatal so the daemon doesn't spin forever on an unrecoverable
/// error.
pub(crate) fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(
        e.kind(),
        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::ConnectionAborted
    ) {
        return true;
    }
    // EMFILE (24) / ENFILE (23): too many open files. std maps these to
    // ErrorKind::Other (no stable variant), so match on the raw errno, the
    // single most important transient accept() failure for a daemon under a
    // connection burst, since refusing to recover would let one spike kill it.
    #[cfg(unix)]
    if matches!(e.raw_os_error(), Some(24) | Some(23)) {
        return true;
    }
    false
}

enum MassFilesystemMessage {
    Batch(Vec<Chunk>),
    Complete(SourceCoverageGaps),
    Error(String),
}

fn spawn_mass_filesystem_source(
    root: PathBuf,
    max_file_size: u64,
    ignore_paths: Vec<String>,
    respect_default_excludes: bool,
    reader_threads: Option<NonZeroUsize>,
) -> mpsc::Receiver<MassFilesystemMessage> {
    let (sender, receiver) = mpsc::channel(2);
    tokio::task::spawn_blocking(move || {
        let _coverage_guard = match DAEMON_SOURCE_COVERAGE_LOCK.lock() {
            Ok(guard) => guard,
            Err(_) => {
                let _ = sender.blocking_send(MassFilesystemMessage::Error(
                    "daemon: source coverage lock poisoned".to_string(),
                ));
                return;
            }
        };
        let before = keyhog_sources::skip_counts();
        let mut source = keyhog_sources::FilesystemSource::new(root.clone())
            .with_max_file_size(max_file_size)
            .with_ignore_paths(ignore_paths)
            .with_default_excludes(respect_default_excludes);
        if let Some(threads) = reader_threads {
            source = source.with_reader_threads(threads);
        }

        let mut batch = Vec::with_capacity(MASS_BATCH_CHUNKS);
        let mut batch_bytes = 0usize;
        let mut source_failed = 0usize;
        for chunk_result in source.chunks() {
            let chunk = match chunk_result {
                Ok(chunk) => chunk,
                Err(error) => {
                    source_failed = source_failed.saturating_add(1);
                    tracing::warn!(
                        "mass daemon local filesystem source {}: {error}",
                        root.display()
                    );
                    continue;
                }
            };
            let chunks = match crate::subcommands::scan::split_chunk_for_mass(chunk) {
                Ok(chunks) => chunks,
                Err(error) => {
                    source_failed = source_failed.saturating_add(1);
                    tracing::warn!(
                        "mass daemon local filesystem chunk {}: {error:#}",
                        root.display()
                    );
                    continue;
                }
            };
            for chunk in chunks {
                let chunk_bytes = chunk.data.len();
                if !batch.is_empty()
                    && (batch.len() >= MASS_BATCH_CHUNKS
                        || batch_bytes.saturating_add(chunk_bytes) > MASS_BATCH_BYTES)
                {
                    if sender
                        .blocking_send(MassFilesystemMessage::Batch(std::mem::take(&mut batch)))
                        .is_err()
                    {
                        return;
                    }
                    batch = Vec::with_capacity(MASS_BATCH_CHUNKS);
                    batch_bytes = 0;
                }
                batch_bytes = batch_bytes.saturating_add(chunk_bytes);
                batch.push(chunk);
            }
        }
        if !batch.is_empty()
            && sender
                .blocking_send(MassFilesystemMessage::Batch(batch))
                .is_err()
        {
            return;
        }
        let mut gaps = source_coverage_gaps_since(before);
        gaps.source_failed = gaps.source_failed.saturating_add(source_failed);
        let _ = sender.blocking_send(MassFilesystemMessage::Complete(gaps));
    });
    receiver
}

struct MassSession {
    state: Arc<ServerState>,
    dogfood: bool,
    stats: MassScanStats,
    started_at: Instant,
    filesystem_batches: Option<mpsc::Receiver<MassFilesystemMessage>>,
    _fragment_guard: OwnedMutexGuard<()>,
}

impl MassSession {
    fn record(&mut self, batch: &MassBatchDispatch) {
        if !matches!(batch.response, Response::ScanResults { .. }) {
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
    }

    fn finish_stats(&self) -> MassScanStats {
        MassScanStats {
            duration_ms: self.started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64,
            ..self.stats
        }
    }
}

impl Drop for MassSession {
    fn drop(&mut self) {
        self.state.scanner.clear_fragment_cache();
        self.state.active_scans.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn handle_connection(state: Arc<ServerState>, stream: UnixStream) -> Result<()> {
    trust::verify_accepted_peer(&stream)?;
    let mut transport = frame::server_transport(stream);
    let read_timeout = state.request_read_timeout;
    let mut hello_ok = false;
    let mut warm_route_denial: Option<Response> = None;
    let mut mass_session: Option<MassSession> = None;

    loop {
        let request = match tokio::time::timeout(read_timeout, transport.next()).await {
            Ok(Some(Ok(req))) => req,
            Ok(None) => break,
            Ok(Some(Err(e))) => return Err(e),
            Err(_elapsed) => {
                anyhow::bail!(
                    "daemon: connection idle for {}s without a complete request; \
                     closing it to reclaim the connection slot. Restart the daemon with \
                     --request-timeout-secs <N> for large bounded batches.",
                    read_timeout.as_secs()
                );
            }
        };
        if !hello_ok {
            if !matches!(request, Request::Hello) {
                transport
                    .send(Response::Error {
                        message: "daemon: first request on a connection must be Hello \
                             (wire and corpus identity handshake required before scan or shutdown)"
                            .to_string(),
                    })
                    .await?;
                break;
            }
            hello_ok = true;
        }

        let response = match request {
            Request::MassBegin { dogfood } => {
                if !state.mass_service {
                    Response::Error {
                        message: "daemon: mass transaction refused because this service was not \
                                  started with `keyhog daemon start --mass`"
                            .to_string(),
                    }
                } else if mass_session.is_some() {
                    Response::Error {
                        message: "daemon: this connection already owns an active mass transaction"
                            .to_string(),
                    }
                } else if let Some(denial) = warm_route_denial.as_ref() {
                    denial.clone()
                } else {
                    let guard = state.fragment_scan_lock.clone().lock_owned().await;
                    state.scanner.clear_fragment_cache();
                    state.active_scans.fetch_add(1, Ordering::Relaxed);
                    mass_session = Some(MassSession {
                        state: state.clone(),
                        dogfood,
                        stats: MassScanStats::default(),
                        started_at: Instant::now(),
                        filesystem_batches: None,
                        _fragment_guard: guard,
                    });
                    Response::MassReady
                }
            }
            Request::MassBatch { chunks } => match mass_session.as_mut() {
                Some(session) if session.filesystem_batches.is_some() => Response::Error {
                    message: "daemon: MassBatch cannot interleave with active daemon-local filesystem acquisition"
                        .to_string(),
                },
                Some(session) => {
                    let batch = scan_mass_batch(&state, chunks, session.dogfood).await;
                    session.record(&batch);
                    batch.response
                }
                None => Response::Error {
                    message: "daemon: MassBatch requires an active MassBegin transaction"
                        .to_string(),
                },
            },
            Request::MassFilesystemBegin {
                root,
                max_file_size,
                ignore_paths,
                respect_default_excludes,
                reader_threads,
            } => match mass_session.as_mut() {
                Some(session) if session.filesystem_batches.is_some() => Response::Error {
                    message: "daemon: finish the active daemon-local filesystem source before starting another"
                        .to_string(),
                },
                Some(session) => {
                    let resolved = resolve_scan_target(&root, None);
                    let reader_threads = match reader_threads {
                        Some(0) => Err(
                            "daemon: MassFilesystemBegin reader_threads must be positive"
                                .to_string(),
                        ),
                        Some(value) => Ok(NonZeroUsize::new(value)),
                        None => Ok(None),
                    };
                    match (resolved, reader_threads) {
                        (Ok(root), Ok(reader_threads)) => {
                            session.filesystem_batches = Some(spawn_mass_filesystem_source(
                                root,
                                max_file_size,
                                ignore_paths,
                                respect_default_excludes,
                                reader_threads,
                            ));
                            Response::MassFilesystemReady
                        }
                        (Err(message), _) | (_, Err(message)) => Response::Error { message },
                    }
                }
                None => Response::Error {
                    message:
                        "daemon: MassFilesystemBegin requires an active MassBegin transaction"
                            .to_string(),
                },
            },
            Request::MassFilesystemNext => match mass_session.as_mut() {
                Some(session) => match session.filesystem_batches.as_mut() {
                    Some(receiver) => match receiver.recv().await {
                        Some(MassFilesystemMessage::Batch(chunks)) => {
                            let batch = scan_mass_batch(&state, chunks, session.dogfood).await;
                            session.record(&batch);
                            batch.response
                        }
                        Some(MassFilesystemMessage::Complete(source_coverage_gaps)) => {
                            session.filesystem_batches = None;
                            Response::MassFilesystemComplete {
                                source_coverage_gaps,
                            }
                        }
                        Some(MassFilesystemMessage::Error(message)) => {
                            session.filesystem_batches = None;
                            Response::Error { message }
                        }
                        None => {
                            session.filesystem_batches = None;
                            Response::Error {
                                message: "daemon: local filesystem producer ended without a completion receipt"
                                    .to_string(),
                            }
                        }
                    },
                    None => Response::Error {
                        message: "daemon: MassFilesystemNext requires an active daemon-local filesystem source"
                            .to_string(),
                    },
                },
                None => Response::Error {
                    message: "daemon: MassFilesystemNext requires an active MassBegin transaction"
                        .to_string(),
                },
            },
            Request::MassEnd
                if mass_session
                    .as_ref()
                    .is_some_and(|session| session.filesystem_batches.is_some()) =>
            {
                Response::Error {
                    message: "daemon: MassEnd refused while daemon-local filesystem acquisition is active"
                        .to_string(),
                }
            }
            Request::MassEnd => match mass_session.take() {
                Some(session) => {
                    let stats = session.finish_stats();
                    state.scans_served.fetch_add(1, Ordering::Relaxed);
                    drop(session);
                    Response::MassComplete { stats }
                }
                None => Response::Error {
                    message: "daemon: MassEnd requires an active MassBegin transaction".to_string(),
                },
            },
            other if mass_session.is_some() => Response::Error {
                message: format!(
                    "daemon: active mass transaction accepts only mass batch, filesystem, or end requests; got {}",
                    crate::daemon::protocol::request_kind(&other)
                ),
            },
            other @ (Request::ScanText { .. } | Request::ScanPath { .. }) => {
                match warm_route_denial.as_ref() {
                    Some(denial) => denial.clone(),
                    None => dispatch(&state, other).await,
                }
            }
            other => dispatch(&state, other).await,
        };
        if let Response::Hello { warm_backend, .. } = &response {
            warm_route_denial = warm_route_error(warm_backend);
        }
        let is_shutdown_ack = matches!(response, Response::Shutdown);
        transport.send(response).await?;
        if is_shutdown_ack {
            state.shutdown.notify_waiters();
            break;
        }
    }
    Ok(())
}


async fn dispatch(state: &ServerState, request: Request) -> Response {
    match request {
        Request::Hello => Response::Hello {
            wire_version: WIRE_VERSION,
            keyhog_version: KEYHOG_VERSION.to_string(),
            git_hash: keyhog_core::git_hash().to_string(),
            detector_rules_digest: state.detector_rules_digest.clone(),
            backend_policy: state.backend_policy().to_string(),
            detector_count: state.detector_count,
            uptime_secs: state.uptime_secs(),
            warm_backend: state.warm_backend_status(),
            mass_service: state.mass_service,
            mass_gpu_primary_required: state.mass_gpu_primary_required,
        },
        Request::Health => match state.last_backend_fault.lock() {
            Ok(last_backend_fault) => Response::Health {
                uptime_secs: state.uptime_secs(),
                scans_served: state.scans_served.load(Ordering::Relaxed),
                active_scans: state.active_scans.load(Ordering::Relaxed),
                detector_count: state.detector_count,
                backend_recoveries: state.backend_recoveries.load(Ordering::Relaxed),
                last_backend_fault: last_backend_fault.clone(),
                warm_backend: state.warm_backend_status(),
            },
            Err(_) => Response::Error {
                message: "daemon: backend-recovery health lock is poisoned; restart the daemon"
                    .to_string(),
            },
        },
        Request::ScanText {
            path,
            text,
            dogfood,
        } => scan_text(state, path, text, dogfood).await,
        Request::ScanPath {
            path,
            working_dir,
            dogfood,
        } => scan_path(state, path, working_dir, dogfood).await,
        Request::MassBegin { .. }
        | Request::MassBatch { .. }
        | Request::MassFilesystemBegin { .. }
        | Request::MassFilesystemNext
        | Request::MassEnd => Response::Error {
            message: "daemon: mass transaction request reached invalid dispatch state".to_string(),
        },
        Request::Shutdown => Response::Shutdown,
    }
}

async fn scan_text(
    state: &ServerState,
    path: Option<String>,
    text: String,
    dogfood: bool,
) -> Response {
    state.active_scans.fetch_add(1, Ordering::Relaxed);
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
    let _fragment_guard = fragment_scan_lock.lock_owned().await;
    scanner.clear_fragment_cache();
    // Hand the actual scan to a blocking thread - calibrated backend scanning
    // is CPU-heavy and not async-aware. Without `spawn_blocking` a
    // large scan would stall the tokio reactor and block every
    // other connection's framing reads.
    let res = tokio::task::spawn_blocking(move || -> Result<_> {
        let (matches, backend_recovery) = keyhog_scanner::telemetry::with_scan_telemetry(
            &telemetry,
            || -> Result<(Vec<RawMatch>, Option<BackendRecoveryStatus>)> {
                scanner.clear_fragment_cache();
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
                    .map(backend_recovery_status_from_receipt)
                    .or_else(|| {
                        selection.autoroute_recovery.as_ref().map(|recovery| {
                            autoroute_state_recovery_status(
                                std::slice::from_ref(&chunk),
                                selection.backend,
                                recovery,
                            )
                        })
                    });
                scanner.clear_fragment_cache();
                Ok((
                    outcome.per_chunk.into_iter().flatten().collect(),
                    backend_recovery,
                ))
            },
        )?;
        let telemetry = telemetry.drain();
        Ok((matches, telemetry, backend_recovery))
    })
    .await;
    state.active_scans.fetch_sub(1, Ordering::Relaxed);
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok(Ok((matches, telemetry, backend_recovery))) => {
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

async fn scan_path(
    state: &ServerState,
    path: String,
    working_dir: Option<String>,
    dogfood: bool,
) -> Response {
    let resolved = match resolve_scan_target(&path, working_dir.as_deref()) {
        Ok(target) => target,
        Err(message) => return Response::Error { message },
    };

    state.active_scans.fetch_add(1, Ordering::Relaxed);
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
    if dogfood {
        telemetry.enable_dogfood();
    }
    let _fragment_guard = fragment_scan_lock.lock_owned().await;
    scanner.clear_fragment_cache();
    type ScanOutput = (
        Vec<RawMatch>,
        keyhog_scanner::telemetry::ScanTelemetrySnapshot,
        SourceCoverageGaps,
        Option<BackendRecoveryStatus>,
    );
    let res = tokio::task::spawn_blocking(move || -> Result<ScanOutput> {
        let (chunks, source_coverage_gaps) = daemon_scan_path_chunks(&resolved_owned)?;
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
                    .map(backend_recovery_status_from_receipt)
                    .or_else(|| {
                        selection.autoroute_recovery.as_ref().map(|recovery| {
                            autoroute_state_recovery_status(&chunks, selection.backend, recovery)
                        })
                    });
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
    })
    .await;
    state.active_scans.fetch_sub(1, Ordering::Relaxed);
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok(Ok((matches, telemetry, source_coverage_gaps, backend_recovery))) => {
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

struct MassBatchDispatch {
    response: Response,
    chunks: u64,
    bytes: u64,
    gpu: bool,
}

impl MassBatchDispatch {
    fn error(message: String) -> Self {
        Self {
            response: Response::Error { message },
            chunks: 0,
            bytes: 0,
            gpu: false,
        }
    }
}

fn validate_mass_batch(chunks: &[Chunk]) -> std::result::Result<(u64, usize), String> {
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

async fn scan_mass_batch(
    state: &ServerState,
    chunks: Vec<Chunk>,
    dogfood: bool,
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
    let res = tokio::task::spawn_blocking(move || -> Result<_> {
        if chunks.iter().all(|chunk| chunk.data.is_empty()) {
            return Ok((Vec::new(), telemetry.drain(), None, false));
        }
        let (matches, backend_recovery, gpu) =
            keyhog_scanner::telemetry::with_scan_telemetry(
                &telemetry,
                || -> Result<(Vec<RawMatch>, Option<BackendRecoveryStatus>, bool)> {
                    let selection =
                        router.choose_with_plan(scanner.as_ref(), backend_override, &chunks)?;
                    let outcome = crate::orchestrator::scan_selected_batch(
                        scanner.as_ref(),
                        &chunks,
                        selection.backend,
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
                        .map(backend_recovery_status_from_receipt)
                        .or_else(|| {
                            selection.autoroute_recovery.as_ref().map(|recovery| {
                                autoroute_state_recovery_status(
                                    &chunks,
                                    selection.backend,
                                    recovery,
                                )
                            })
                        });
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
    })
    .await;

    match res {
        Ok(Ok((matches, telemetry, backend_recovery, gpu))) => {
            if let Some(recovery) = backend_recovery.clone() {
                if let Err(error) = state.record_backend_recovery(recovery) {
                    return MassBatchDispatch::error(format!(
                        "daemon: mass batch recovered, but health recording failed: {error:#}"
                    ));
                }
            }
            MassBatchDispatch {
                response: scan_results_response(
                    None,
                    matches,
                    telemetry,
                    SourceCoverageGaps::default(),
                    backend_recovery,
                ),
                chunks: chunk_count,
                bytes: batch_bytes as u64,
                gpu,
            }
        }
        Ok(Err(error)) => {
            MassBatchDispatch::error(format!("daemon: mass batch failed: {error:#}"))
        }
        Err(error) => MassBatchDispatch::error(format!(
            "daemon: mass batch task panicked or was cancelled: {error:#}"
        )),
    }
}

fn scan_results_response(
    path: Option<String>,
    matches: Vec<RawMatch>,
    telemetry: keyhog_scanner::telemetry::ScanTelemetrySnapshot,
    source_coverage_gaps: SourceCoverageGaps,
    backend_recovery: Option<BackendRecoveryStatus>,
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
    }
}

fn backend_recovery_status_from_receipt(
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

fn autoroute_state_recovery_status(
    chunks: &[Chunk],
    recovery_backend: ScanBackend,
    recovery: &crate::orchestrator::AutorouteStateRecovery,
) -> BackendRecoveryStatus {
    let recovered_ranges = chunks
        .iter()
        .enumerate()
        .filter(|(_, chunk)| !chunk.data.is_empty())
        .map(|(chunk_index, chunk)| RecoveredInputRangeStatus {
            chunk_index,
            byte_start: 0,
            byte_end: chunk.data.len(),
        })
        .collect::<Vec<_>>();
    BackendRecoveryStatus {
        failed_backend: "autoroute-invalid".to_string(),
        recovery_backend: recovery_backend.label().to_string(),
        recovered_chunks: recovered_ranges.len(),
        recovered_bytes: recovered_ranges
            .iter()
            .map(|range| (range.byte_end - range.byte_start) as u64)
            .sum(),
        recovered_ranges,
        reason: recovery.reason.clone(),
    }
}

fn daemon_scan_path_chunks(path: &Path) -> Result<(Vec<Chunk>, SourceCoverageGaps)> {
    let _coverage_guard = DAEMON_SOURCE_COVERAGE_LOCK
        .lock()
        .map_err(|_| anyhow::anyhow!("daemon: source coverage lock poisoned"))?;
    let before = keyhog_sources::skip_counts();
    let source = keyhog_sources::FilesystemSource::new(path.to_path_buf());
    let mut chunks = Vec::new();
    for chunk in source.chunks() {
        let chunk = chunk.with_context(|| {
            format!("daemon: expanding filesystem source for {}", path.display())
        })?;
        if chunk.data.len() > crate::orchestrator::COALESCED_CHUNK_SCAN_CEILING_BYTES {
            let chunk_path = match chunk.metadata.path.as_deref() {
                Some(path) => path.to_owned(),
                None => path.display().to_string(),
            };
            anyhow::bail!(
                "daemon: refusing chunk over {} MiB from {}. Pass --daemon=off to use the full in-process scanner.",
                crate::orchestrator::COALESCED_CHUNK_SCAN_CEILING_MB,
                chunk_path
            );
        }
        chunks.push(chunk);
    }
    Ok((chunks, source_coverage_gaps_since(before)))
}

fn source_coverage_gaps_since(before: keyhog_sources::SkipCounts) -> SourceCoverageGaps {
    let after = keyhog_sources::skip_counts();
    SourceCoverageGaps {
        over_max_size: after.over_max_size.saturating_sub(before.over_max_size),
        binary: after.binary.saturating_sub(before.binary),
        unreadable: after.unreadable.saturating_sub(before.unreadable),
        git_object_unreadable: after
            .git_object_unreadable
            .saturating_sub(before.git_object_unreadable),
        archive_truncated: after
            .archive_truncated
            .saturating_sub(before.archive_truncated),
        binary_section_name_unresolved: after
            .binary_section_name_unresolved
            .saturating_sub(before.binary_section_name_unresolved),
        source_truncated: after
            .source_truncated
            .saturating_sub(before.source_truncated),
        structured_source_parse_failures: after
            .structured_source_parse_failures
            .saturating_sub(before.structured_source_parse_failures),
        archive_duplicate_scan_unavailable: after
            .archive_duplicate_scan_unavailable
            .saturating_sub(before.archive_duplicate_scan_unavailable),
        git_lfs_pointer: after.git_lfs_pointer.saturating_sub(before.git_lfs_pointer),
        source_failed: 0,
    }
}
// Sibling file (daemon/server_tests.rs), not server/ subdir.
#[path = "server_tests.rs"]
mod server_tests;

#[doc(hidden)]
pub(crate) mod testing {
    pub(crate) use crate::daemon::trust::testing::{
        ensure_private_socket_dir, remove_stale_socket_if_trusted, verify_accepted_peer,
    };

    pub(crate) async fn finish_daemon_service_for_test(
        socket_path: std::path::PathBuf,
        fixture: crate::testing::DaemonTerminalFixture,
    ) -> anyhow::Result<()> {
        let accept_task = tokio::spawn(async move {
            let shutdown = tokio::sync::Notify::new();
            match fixture {
                crate::testing::DaemonTerminalFixture::CleanShutdown => Ok(()),
                crate::testing::DaemonTerminalFixture::AcceptLoopPanic => {
                    panic!("injected accept loop panic")
                }
                crate::testing::DaemonTerminalFixture::FatalAccept(error) => {
                    super::handle_accept_error(&shutdown, error).await
                }
                crate::testing::DaemonTerminalFixture::ConnectionHandlerSpawn(error) => {
                    Err(super::handle_connection_spawn_error(&shutdown, error))
                }
            }
        });
        super::finish_daemon_service(&socket_path, accept_task).await
    }
}
