//! Daemon server: long-lived process that holds a compiled scanner
//! and serves scan requests over a Unix socket.

use crate::daemon::frame;
use crate::daemon::protocol::{Request, Response, SourceCoverageGaps, WIRE_VERSION};
use crate::daemon::trust;
use crate::style;
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, RawMatch, Source};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Notify, Semaphore};

const KEYHOG_VERSION: &str = env!("CARGO_PKG_VERSION");
static DAEMON_SOURCE_COVERAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const DEFAULT_REQUEST_READ_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone, Copy)]
pub struct ServerOptions {
    /// Maximum wall-clock time a single client request may take to fully arrive
    /// once the connection is otherwise idle-waiting for it. Bounds a slowloris
    /// / half-frame stall: a peer that announces a frame length (up to the
    /// 64 MiB `MAX_FRAME_BYTES`) then sends the body slowly, or never, would
    /// otherwise hold a `connection_limit` semaphore permit forever.
    pub request_read_timeout: Duration,
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
    // Fragment reassembly is scanner-owned mutable state. Until it becomes an
    // explicit per-scan context, serialize clear/scan/clear so independent
    // clients can never combine secret fragments across requests.
    fragment_scan_lock: Arc<std::sync::Mutex<()>>,
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
            fragment_scan_lock: Arc::new(std::sync::Mutex::new(())),
            connection_limit: Arc::new(Semaphore::new(max_conns)),
        }
    }

    fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    fn backend_policy(&self) -> &'static str {
        self.backend_override
            .map(ScanBackend::label)
            .unwrap_or("autoroute")
    }
}

/// Run the daemon until a `Shutdown` request or terminal listener failure.
/// The compiled scanner is built once before the
/// listener accepts so the first client connection doesn't pay the
/// init cost (which is the whole point of running a daemon).
pub async fn run(
    socket_path: PathBuf,
    detectors: Vec<DetectorSpec>,
    options: ServerOptions,
) -> Result<()> {
    run_with_backend_override(socket_path, detectors, options, None).await
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
    let (scanner, router, detector_count) =
        compile_daemon_scan_runtime(detectors, backend_override)?;
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
    ));

    announce_daemon_ready(&socket_path, detector_count);
    let accept_task = spawn_accept_loop(listener, state.clone());

    finish_daemon_service(&socket_path, accept_task).await
}

async fn finish_daemon_service(
    socket_path: &Path,
    accept_task: tokio::task::JoinHandle<std::result::Result<(), DaemonServiceFailure>>,
) -> Result<()> {
    let terminal_outcome = match accept_task.await {
        Ok(outcome) => outcome,
        Err(error) => Err(DaemonServiceFailure::AcceptLoopTask(error.to_string())),
    };
    let cleanup = remove_daemon_socket_on_shutdown(socket_path);
    match (terminal_outcome, cleanup) {
        (Ok(()), cleanup) => cleanup,
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
    Ok((scanner, router, detector_count))
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

fn announce_daemon_ready(socket_path: &Path, detector_count: usize) {
    eprintln!(
        "keyhog daemon ready on {} ({} detectors, wire={})",
        socket_path.display(),
        detector_count,
        WIRE_VERSION,
    );
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

async fn handle_connection(state: Arc<ServerState>, stream: UnixStream) -> Result<()> {
    // Belt-and-suspenders peer-cred gate, symmetric with the client's
    // `verify_connected_peer`. The 0600 socket + 0700 parent dir are the primary
    // boundary; this rejects a cross-uid peer that reaches us through a bind-race
    // before the socket is chmod-tightened, or a root connection.
    trust::verify_accepted_peer(&stream)?;
    let mut transport = frame::server_transport(stream);
    let read_timeout = state.request_read_timeout;
    loop {
        // Bound the per-request read so a half-frame / slowloris stall (a peer
        // that announces a frame length then sends the body slowly or never)
        // cannot hold this connection's `connection_limit` permit forever and
        // starve other same-uid clients. keyhog daemon clients do one
        // round-trip then disconnect, so a connection idle past the timeout is
        // either finished (should have closed) or stuck, closing it is correct
        // and frees the permit.
        let request = match tokio::time::timeout(read_timeout, transport.next()).await {
            Ok(Some(Ok(req))) => req,
            // Clean EOF: peer closed. Done.
            Ok(None) => break,
            // Frame/parse error: propagate so the connection is dropped.
            Ok(Some(Err(e))) => return Err(e),
            Err(_elapsed) => {
                anyhow::bail!(
                    "daemon: connection idle for {}s without a complete request; \
                 closing it to reclaim the connection slot (a stuck or slow \
                 client). Restart the daemon with --request-timeout-secs \
                 <N> for very large pre-warmed batches.",
                    read_timeout.as_secs()
                );
            }
        };
        let response = dispatch(&state, request).await;
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
        },
        Request::Health => Response::Health {
            uptime_secs: state.uptime_secs(),
            scans_served: state.scans_served.load(Ordering::Relaxed),
            active_scans: state.active_scans.load(Ordering::Relaxed),
            detector_count: state.detector_count,
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
    let fragment_scan_lock = state.fragment_scan_lock.clone();
    let chunk_path = path.clone();
    let telemetry = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
    if dogfood {
        telemetry.enable_dogfood();
    }
    // Hand the actual scan to a blocking thread - calibrated backend scanning
    // is CPU-heavy and not async-aware. Without `spawn_blocking` a
    // large scan would stall the tokio reactor and block every
    // other connection's framing reads.
    let res = tokio::task::spawn_blocking(move || -> Result<_> {
        let matches = keyhog_scanner::telemetry::with_scan_telemetry(
            &telemetry,
            || -> Result<Vec<RawMatch>> {
                let _fragment_guard = fragment_scan_lock
                    .lock()
                    .map_err(|_| anyhow::anyhow!("daemon fragment scan lock is poisoned"))?;
                scanner.clear_fragment_cache();
                let chunk = Chunk {
                    data: text.into(),
                    metadata: ChunkMetadata {
                        source_type: "stdin".into(),
                        path: chunk_path.map(Into::into),
                        ..Default::default()
                    },
                };
                let backend = router.choose(backend_override, std::slice::from_ref(&chunk))?;
                let matches = scanner.scan_with_backend(&chunk, backend);
                scanner.clear_fragment_cache();
                Ok(matches)
            },
        )?;
        let telemetry = telemetry.drain();
        Ok((matches, telemetry))
    })
    .await;
    state.active_scans.fetch_sub(1, Ordering::Relaxed);
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok(Ok((matches, telemetry))) => {
            scan_results_response(path, matches, telemetry, SourceCoverageGaps::default())
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
/// client's absolute `working_dir`; a relative path with no usable working_dir
/// fails closed with an actionable error. The client sends `working_dir=None`
/// only when its own `std::env::current_dir()` failed (see subcommands/scan.rs),
/// and the daemon's own cwd is unrelated to what the client wants scanned -
/// resolving against it would silently scan the wrong tree (LAW10: no silent
/// fallback). `pub` only so the external resolution regression test can reach
/// it; not protocol surface.
pub fn resolve_scan_target(path: &str, working_dir: Option<&str>) -> Result<PathBuf, String> {
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
    let fragment_scan_lock = state.fragment_scan_lock.clone();
    let resolved_owned = resolved.clone();
    let telemetry = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
    if dogfood {
        telemetry.enable_dogfood();
    }
    type ScanOutput = (
        Vec<RawMatch>,
        keyhog_scanner::telemetry::ScanTelemetrySnapshot,
        SourceCoverageGaps,
    );
    let res = tokio::task::spawn_blocking(move || -> Result<ScanOutput> {
        let (chunks, source_coverage_gaps) = daemon_scan_path_chunks(&resolved_owned)?;
        if chunks.is_empty() {
            return Ok((Vec::new(), telemetry.drain(), source_coverage_gaps));
        }
        let matches = keyhog_scanner::telemetry::with_scan_telemetry(
            &telemetry,
            || -> Result<Vec<RawMatch>> {
                let _fragment_guard = fragment_scan_lock
                    .lock()
                    .map_err(|_| anyhow::anyhow!("daemon fragment scan lock is poisoned"))?;
                scanner.clear_fragment_cache();
                let backend = router.choose(backend_override, &chunks)?;
                let mut per_chunk = scanner.scan_coalesced_with_backend(&chunks, backend);
                scanner.clear_fragment_cache();
                crate::inline_suppression::attach_inline_suppression_context(
                    &chunks,
                    &mut per_chunk,
                );
                Ok(per_chunk.into_iter().flatten().collect())
            },
        )?;
        Ok((matches, telemetry.drain(), source_coverage_gaps))
    })
    .await;
    state.active_scans.fetch_sub(1, Ordering::Relaxed);
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok(Ok((matches, telemetry, source_coverage_gaps))) => scan_results_response(
            Some(resolved.to_string_lossy().into_owned()),
            matches,
            telemetry,
            source_coverage_gaps,
        ),
        Ok(Err(e)) => Response::Error {
            message: format!("daemon: scan_path failed: {e:#}"),
        },
        Err(e) => Response::Error {
            message: format!("daemon: scan task panicked or was cancelled: {e:#}"),
        },
    }
}

fn scan_results_response(
    path: Option<String>,
    matches: Vec<RawMatch>,
    telemetry: keyhog_scanner::telemetry::ScanTelemetrySnapshot,
    source_coverage_gaps: SourceCoverageGaps,
) -> Response {
    Response::ScanResults {
        path,
        matches,
        engine_example_suppressions: telemetry.example_suppressions,
        dogfood_events: telemetry.dogfood_events,
        static_recovery_rejections: telemetry.static_recovery_rejections,
        dogfood_detail_events_dropped: telemetry.dogfood_detail_events_dropped,
        source_coverage_gaps,
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
    }
}

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
