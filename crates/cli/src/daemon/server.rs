//! Daemon server: long-lived process that holds a compiled scanner
//! and serves scan requests over a Unix socket.

use crate::daemon::frame;
use crate::daemon::protocol::{Request, Response, WIRE_VERSION};
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

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            request_read_timeout: Duration::from_secs(DEFAULT_REQUEST_READ_TIMEOUT_SECS),
        }
    }
}

/// Default socket path. Prefers `$XDG_RUNTIME_DIR/keyhog.sock`
/// (per-user, tmpfs-backed, auto-cleaned on logout) and falls back
/// to `~/.cache/keyhog/server.sock` when the runtime dir isn't
/// exported (e.g. inside Docker containers, CI runners).
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
    request_read_timeout: Duration,
    backend_override: Option<ScanBackend>,
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
            request_read_timeout: options.request_read_timeout,
            backend_override,
            connection_limit: Arc::new(Semaphore::new(max_conns)),
        }
    }

    fn uptime_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }
}

/// Run the daemon until a `Shutdown` request comes in or the
/// listener closes. The compiled scanner is built once before the
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
    let (scanner, router, detector_count) = compile_daemon_scan_runtime(detectors)?;
    let listener = bind_trusted_daemon_socket(&socket_path)?;
    let shutdown = Arc::new(Notify::new());
    let state = Arc::new(ServerState::new(
        scanner,
        router,
        shutdown.clone(),
        detector_count,
        options,
        backend_override,
    ));

    announce_daemon_ready(&socket_path, detector_count);
    let accept_task = spawn_accept_loop(listener, state.clone());

    shutdown.notified().await;
    accept_task
        .await
        .context("daemon: accept loop task failed during shutdown")?;
    remove_daemon_socket_on_shutdown(&socket_path)?;
    Ok(())
}

fn compile_daemon_scan_runtime(
    detectors: Vec<DetectorSpec>,
) -> Result<(
    Arc<CompiledScanner>,
    crate::orchestrator::CachedBackendRouter,
    usize,
)> {
    let scan_runtime = crate::orchestrator::compile_default_scan_runtime(detectors, |error| {
        anyhow::anyhow!("daemon: compiling scanner from detector specs: {error}")
    })?;
    let detector_count = scan_runtime.detector_count();
    // The daemon is long-lived and serves many scan requests; pay the lazy
    // regex compile once, up front and in parallel, so no client request eats a
    // detector's first-use compile latency.
    scan_runtime.warm();
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
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_accept_loop(listener, state))
}

async fn run_accept_loop(listener: UnixListener, state: Arc<ServerState>) {
    loop {
        tokio::select! {
            _ = state.shutdown.notified() => break,
            conn = listener.accept() => {
                match conn {
                    Ok((stream, _addr)) => {
                        if spawn_connection_handler(state.clone(), stream).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        if handle_accept_error(&state, e).await {
                            continue;
                        }
                        break;
                    }
                }
            }
        }
    }
}

async fn spawn_connection_handler(
    state: Arc<ServerState>,
    stream: UnixStream,
) -> std::result::Result<(), ()> {
    let limiter = state.connection_limit.clone();
    // Backpressure: refuse to spawn another handler until a permit is available.
    // A permit drop at the end of the spawned task releases the slot.
    let permit = limiter.acquire_owned().await.map_err(|_closed| ())?;
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = handle_connection(state, stream).await {
            tracing::warn!("daemon: connection ended with error: {e:#}");
        }
    });
    Ok(())
}

async fn handle_accept_error(state: &ServerState, error: std::io::Error) -> bool {
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
        return true;
    }

    let palette = style::for_stderr();
    eprintln!(
        "{} keyhog daemon: listener accept failed fatally ({error}); \
         the daemon can no longer accept connections and is \
         shutting down. Restart it with `keyhog daemon start`.",
        style::fail("FAIL", &palette)
    );
    state.shutdown.notify_waiters();
    false
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

/// Classify an `accept()` I/O error as transient (recoverable — back off and
/// keep serving) versus fatal (the listening socket is unusable — shut down).
///
/// Transient cases are the ones a momentary spike produces and that clear on
/// their own once the backlog drains: per-process / system-wide fd exhaustion
/// (`EMFILE` / `ENFILE`, surfaced by std as `Other`), a connection the peer
/// aborted between the SYN and our accept (`ECONNABORTED`), an interrupted
/// syscall (`EINTR` -> `Interrupted`), and a transient resource shortage
/// (`WouldBlock`). Everything else (e.g. the socket fd closed under us) is
/// treated as fatal so the daemon doesn't spin forever on an unrecoverable
/// error.
pub fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(
        e.kind(),
        ErrorKind::Interrupted | ErrorKind::WouldBlock | ErrorKind::ConnectionAborted
    ) {
        return true;
    }
    // EMFILE (24) / ENFILE (23): too many open files. std maps these to
    // ErrorKind::Other (no stable variant), so match on the raw errno — the
    // single most important transient accept() failure for a daemon under a
    // connection burst, since refusing to recover would let one spike kill it.
    #[cfg(unix)]
    if matches!(e.raw_os_error(), Some(24) | Some(23)) {
        return true;
    }
    false
}

async fn handle_connection(state: Arc<ServerState>, stream: UnixStream) -> Result<()> {
    let mut transport = frame::server_transport(stream);
    let read_timeout = state.request_read_timeout;
    loop {
        // Bound the per-request read so a half-frame / slowloris stall (a peer
        // that announces a frame length then sends the body slowly or never)
        // cannot hold this connection's `connection_limit` permit forever and
        // starve other same-uid clients. keyhog daemon clients do one
        // round-trip then disconnect, so a connection idle past the timeout is
        // either finished (should have closed) or stuck — closing it is correct
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
            detector_count: state.detector_count,
            uptime_secs: state.uptime_secs(),
        },
        Request::Health => Response::Health {
            uptime_secs: state.uptime_secs(),
            scans_served: state.scans_served.load(Ordering::Relaxed),
            active_scans: state.active_scans.load(Ordering::Relaxed),
            detector_count: state.detector_count,
        },
        Request::ScanText { path, text } => scan_text(state, path, text).await,
        Request::ScanPath { path, working_dir } => scan_path(state, path, working_dir).await,
        Request::Shutdown => Response::Shutdown,
    }
}

async fn scan_text(state: &ServerState, path: Option<String>, text: String) -> Response {
    state.active_scans.fetch_add(1, Ordering::Relaxed);
    let scanner = state.scanner.clone();
    let router = state.router.clone();
    let backend_override = state.backend_override;
    let chunk_path = path.clone();
    let telemetry = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
    // Hand the actual scan to a blocking thread - calibrated backend scanning
    // is CPU-heavy and not async-aware. Without `spawn_blocking` a
    // large scan would stall the tokio reactor and block every
    // other connection's framing reads.
    let res = tokio::task::spawn_blocking(move || -> Result<_> {
        let matches = keyhog_scanner::telemetry::with_scan_telemetry(
            &telemetry,
            || -> Result<Vec<RawMatch>> {
                let chunk = Chunk {
                    data: text.into(),
                    metadata: ChunkMetadata {
                        source_type: "stdin".into(),
                        path: chunk_path,
                        ..Default::default()
                    },
                };
                let backend = router.choose(backend_override, std::slice::from_ref(&chunk))?;
                Ok(scanner.scan_with_backend(&chunk, backend))
            },
        )?;
        let (engine_example_suppressions, dogfood_events) = drain_daemon_scan_telemetry(&telemetry);
        Ok((matches, engine_example_suppressions, dogfood_events))
    })
    .await;
    state.active_scans.fetch_sub(1, Ordering::Relaxed);
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok(Ok((matches, engine_example_suppressions, dogfood_events))) => Response::ScanResults {
            path,
            matches,
            engine_example_suppressions,
            dogfood_events,
        },
        Ok(Err(e)) => Response::Error {
            message: format!("daemon: scan_text failed: {e:#}"),
        },
        Err(e) => Response::Error {
            message: format!("daemon: scan task panicked or was cancelled: {e:#}"),
        },
    }
}

async fn scan_path(state: &ServerState, path: String, working_dir: Option<String>) -> Response {
    let resolved = if Path::new(&path).is_absolute() {
        PathBuf::from(&path)
    } else if let Some(wd) = working_dir.as_deref() {
        PathBuf::from(wd).join(&path)
    } else {
        PathBuf::from(&path)
    };

    state.active_scans.fetch_add(1, Ordering::Relaxed);
    let scanner = state.scanner.clone();
    let router = state.router.clone();
    let backend_override = state.backend_override;
    let resolved_owned = resolved.clone();
    let telemetry = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
    type ScanOutput = (
        Vec<RawMatch>,
        u64,
        Vec<keyhog_scanner::telemetry::DogfoodEvent>,
    );
    let res = tokio::task::spawn_blocking(move || -> Result<ScanOutput> {
        let chunks = daemon_scan_path_chunks(&resolved_owned)?;
        if chunks.is_empty() {
            let (engine_example_suppressions, dogfood_events) =
                drain_daemon_scan_telemetry(&telemetry);
            return Ok((Vec::new(), engine_example_suppressions, dogfood_events));
        }
        let matches = keyhog_scanner::telemetry::with_scan_telemetry(
            &telemetry,
            || -> Result<Vec<RawMatch>> {
                let backend = router.choose(backend_override, &chunks)?;
                let mut per_chunk = scanner.scan_chunks_with_backend(&chunks, backend);
                crate::inline_suppression::attach_inline_suppression_context(
                    &chunks,
                    &mut per_chunk,
                );
                Ok(per_chunk.into_iter().flatten().collect())
            },
        )?;
        let (engine_example_suppressions, dogfood_events) = drain_daemon_scan_telemetry(&telemetry);
        Ok((matches, engine_example_suppressions, dogfood_events))
    })
    .await;
    state.active_scans.fetch_sub(1, Ordering::Relaxed);
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok(Ok((matches, engine_example_suppressions, dogfood_events))) => Response::ScanResults {
            path: Some(resolved.to_string_lossy().into_owned()),
            matches,
            engine_example_suppressions,
            dogfood_events,
        },
        Ok(Err(e)) => Response::Error {
            message: format!("daemon: scan_path failed: {e:#}"),
        },
        Err(e) => Response::Error {
            message: format!("daemon: scan task panicked or was cancelled: {e:#}"),
        },
    }
}

fn daemon_scan_path_chunks(path: &Path) -> Result<Vec<Chunk>> {
    let source = keyhog_sources::FilesystemSource::new(path.to_path_buf());
    let mut chunks = Vec::new();
    for chunk in source.chunks() {
        let chunk = chunk.with_context(|| {
            format!("daemon: expanding filesystem source for {}", path.display())
        })?;
        if chunk.data.len() > 512 * 1024 * 1024 {
            let chunk_path = match chunk.metadata.path.as_deref() {
                Some(path) => path.to_owned(),
                None => path.display().to_string(),
            };
            anyhow::bail!(
                "daemon: refusing chunk over 512 MiB from {}. Pass --no-daemon to use the full in-process scanner.",
                chunk_path
            );
        }
        chunks.push(chunk);
    }
    Ok(chunks)
}

fn drain_daemon_scan_telemetry(
    telemetry: &keyhog_scanner::telemetry::ScanTelemetry,
) -> (u64, Vec<keyhog_scanner::telemetry::DogfoodEvent>) {
    // Drain telemetry alongside the matches so the client can merge per-scan
    // counts into its own process-local counters. Each daemon request owns a
    // `ScanTelemetry` scope, so concurrent requests cannot observe or reset one
    // another's counts/events.
    let snapshot = telemetry.drain();
    (snapshot.example_suppressions, snapshot.dogfood_events)
}

#[doc(hidden)]
pub(crate) mod testing {
    pub(crate) use crate::daemon::trust::testing::{
        ensure_private_socket_dir, remove_stale_socket_if_trusted,
    };
}
