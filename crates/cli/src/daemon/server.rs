//! Daemon server: long-lived process that holds a compiled scanner
//! and serves scan requests over a Unix socket.

use crate::daemon::frame;
use crate::daemon::protocol::{Request, Response, WIRE_VERSION};
use crate::daemon::trust;
use anyhow::{Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, RawMatch};
use keyhog_scanner::CompiledScanner;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Notify, Semaphore};

const KEYHOG_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Maximum wall-clock time a single client request may take to fully arrive
/// once the connection is otherwise idle-waiting for it. Bounds a slowloris /
/// half-frame stall: a peer that announces a frame length (up to the 64 MiB
/// `MAX_FRAME_BYTES`) then sends the body slowly — or never — would otherwise
/// hold a `connection_limit` semaphore permit forever, and enough such
/// connections starve every OTHER same-uid client of the daemon. The socket is
/// 0600 (same-uid trust), so this is a buggy/crashed client (an IDE plugin that
/// opened a socket and died mid-write), not an adversary; the timeout reclaims
/// the permit so one stuck client can't deadlock the daemon. Five minutes is
/// generous for a 64 MiB scan payload over a local Unix socket. Overridable via
/// `KEYHOG_DAEMON_REQUEST_TIMEOUT_SECS` for very large pre-warmed batches.
fn request_read_timeout() -> std::time::Duration {
    const DEFAULT_SECS: u64 = 300;
    let secs = keyhog_core::env_config::u64_at_least_or_default(
        "KEYHOG_DAEMON_REQUEST_TIMEOUT_SECS",
        1,
        DEFAULT_SECS,
    );
    std::time::Duration::from_secs(secs)
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
        scanner: CompiledScanner,
        router: crate::orchestrator::CachedBackendRouter,
        shutdown: Arc<Notify>,
        detector_count: usize,
    ) -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4); // LAW10: absent config => documented default; Tier-A knob, recall-irrelevant
        let max_conns = (cores * 4).clamp(8, 256);
        Self {
            scanner: Arc::new(scanner),
            router: Arc::new(router),
            started_at: Instant::now(),
            scans_served: AtomicU64::new(0),
            active_scans: AtomicU32::new(0),
            shutdown,
            detector_count,
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
pub async fn run(socket_path: PathBuf, detectors: Vec<DetectorSpec>) -> Result<()> {
    let detector_count = detectors.len();
    let scanner = CompiledScanner::compile(detectors.clone())
        .context("daemon: compiling scanner from detector specs")?;
    let router =
        crate::orchestrator::cached_autoroute_router_for_default_config(&scanner, &detectors);
    // The daemon is long-lived and serves many scan requests; pay the lazy
    // regex compile once, up front and in parallel, so no client request
    // eats a detector's first-use compile latency.
    scanner.warm();

    // Process-wide dogfood capture is gated by the `KEYHOG_DOGFOOD`
    // env var on the daemon side. Per-request toggling would require a
    // protocol bump (and could let one client's debug session inflate
    // another client's payload), so the env-var path is the conservative
    // wiring: an operator who wants `keyhog scan --dogfood` to work
    // against the daemon runs `KEYHOG_DOGFOOD=1 keyhog daemon start`.
    if std::env::var_os("KEYHOG_DOGFOOD").is_some() {
        keyhog_scanner::telemetry::enable_dogfood();
        tracing::info!("daemon: dogfood event capture enabled (KEYHOG_DOGFOOD set)");
    }

    if let Some(parent) = socket_path.parent() {
        trust::ensure_private_socket_dir(parent)?;
    }
    // Remove a stale socket file from a previous crashed instance only after
    // the parent dir and stale socket file both pass the daemon trust checks.
    trust::remove_stale_socket_if_trusted(&socket_path)?;

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("daemon: binding Unix socket at {}", socket_path.display()))?;

    // 0600 = user-only. Without this the socket inherits the umask
    // default which on most distros is 0644 - a co-tenant user on
    // the same box could connect and request scans, exposing every
    // credential the scanner finds via its responses.
    trust::set_socket_mode_user_only(&socket_path)?;

    let shutdown = Arc::new(Notify::new());
    let state = Arc::new(ServerState::new(
        scanner,
        router,
        shutdown.clone(),
        detector_count,
    ));

    eprintln!(
        "keyhog daemon ready on {} ({} detectors, wire={})",
        socket_path.display(),
        detector_count,
        WIRE_VERSION,
    );

    let accept_state = state.clone();
    let accept_shutdown = shutdown.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = accept_shutdown.notified() => break,
                conn = listener.accept() => {
                    match conn {
                        Ok((stream, _addr)) => {
                            let s = accept_state.clone();
                            let limiter = s.connection_limit.clone();
                            // Backpressure: refuse to spawn another
                            // handler until a permit is available. A
                            // permit drop at the end of the spawned
                            // task releases the slot. acquire_owned
                            // moves the permit into the task without
                            // a separate handle to plumb through.
                            let permit = match limiter.acquire_owned().await {
                                Ok(p) => p,
                                Err(_closed) => break, // semaphore closed -> shutting down
                            };
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(e) = handle_connection(s, stream).await {
                                    tracing::debug!("daemon: connection ended with error: {e:#}");
                                }
                            });
                        }
                        Err(e) => {
                            // Law 10: a swallowed accept() error silently kills
                            // the daemon's ability to serve while the process
                            // stays alive — `daemon status` keeps reporting
                            // "ready" but every new connection is refused. A
                            // `tracing::error!` here is invisible without
                            // RUST_LOG, so the operator never learns the daemon
                            // went deaf. Surface it LOUDLY on stderr.
                            //
                            // Transient errors (fd exhaustion under a connection
                            // burst, an interrupted syscall, a peer that aborted
                            // mid-handshake) are RECOVERABLE: a permit-bounded
                            // backlog drains and accept() works again. Back off
                            // briefly and keep serving rather than tearing the
                            // daemon down for a momentary spike.
                            if is_transient_accept_error(&e) {
                                eprintln!(
                                    "⚠ keyhog daemon: accept() failed transiently ({e}); \
                                     backing off and continuing to serve"
                                );
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                                continue;
                            }
                            // A genuinely fatal accept error (the listening socket
                            // was unlinked, the fd was closed under us): the
                            // daemon can never serve again. Do NOT leave a deaf
                            // zombie — surface loudly and trigger graceful
                            // shutdown so the process actually exits and a
                            // supervisor / the operator can restart it.
                            eprintln!(
                                "✗ keyhog daemon: listener accept failed fatally ({e}); \
                                 the daemon can no longer accept connections and is \
                                 shutting down. Restart it with `keyhog daemon start`."
                            );
                            accept_shutdown.notify_waiters();
                            break;
                        }
                    }
                }
            }
        }
    });

    shutdown.notified().await;
    let _ = accept_task.await; // LAW10: unused-binding marker; no runtime effect, not a fallback
    let _ = std::fs::remove_file(&socket_path); // LAW10: unused-binding marker; no runtime effect, not a fallback
    Ok(())
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

async fn handle_connection(state: Arc<ServerState>, mut stream: UnixStream) -> Result<()> {
    let (reader, writer) = stream.split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut writer = tokio::io::BufWriter::new(writer);

    let read_timeout = request_read_timeout();
    loop {
        // Bound the per-request read so a half-frame / slowloris stall (a peer
        // that announces a frame length then sends the body slowly or never)
        // cannot hold this connection's `connection_limit` permit forever and
        // starve other same-uid clients. keyhog daemon clients do one
        // round-trip then disconnect, so a connection idle past the timeout is
        // either finished (should have closed) or stuck — closing it is correct
        // and frees the permit.
        let request =
            match tokio::time::timeout(read_timeout, frame::read_request(&mut reader)).await {
                Ok(Ok(Some(req))) => req,
                // Clean EOF: peer closed. Done.
                Ok(Ok(None)) => break,
                // Frame/parse error: propagate so the connection is dropped.
                Ok(Err(e)) => return Err(e),
                Err(_elapsed) => {
                    anyhow::bail!(
                        "daemon: connection idle for {}s without a complete request; \
                     closing it to reclaim the connection slot (a stuck or slow \
                     client). Raise KEYHOG_DAEMON_REQUEST_TIMEOUT_SECS for very \
                     large pre-warmed batches.",
                        read_timeout.as_secs()
                    );
                }
            };
        let response = dispatch(&state, request).await;
        let is_shutdown_ack = matches!(response, Response::Shutdown);
        frame::write_response(&mut writer, &response).await?;
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
                let backend = router.choose(
                    crate::orchestrator::explicit_backend_override(),
                    std::slice::from_ref(&chunk),
                )?;
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
    let resolved_owned = resolved.clone();
    let telemetry = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
    type ScanOutput = (
        Vec<RawMatch>,
        u64,
        Vec<keyhog_scanner::telemetry::DogfoodEvent>,
    );
    let res = tokio::task::spawn_blocking(move || -> Result<ScanOutput> {
        let bytes = std::fs::read(&resolved_owned)
            .with_context(|| format!("daemon: reading {}", resolved_owned.display()))?;
        let Some(text) = keyhog_sources::decode_file_bytes(&bytes) else {
            let (engine_example_suppressions, dogfood_events) =
                drain_daemon_scan_telemetry(&telemetry);
            return Ok((Vec::new(), engine_example_suppressions, dogfood_events));
        };
        let matches = keyhog_scanner::telemetry::with_scan_telemetry(
            &telemetry,
            || -> Result<Vec<RawMatch>> {
                let chunk = Chunk {
                    data: text.into(),
                    metadata: ChunkMetadata {
                        source_type: "filesystem".into(),
                        path: Some(resolved_owned.to_string_lossy().into_owned()),
                        ..Default::default()
                    },
                };
                let backend = router.choose(
                    crate::orchestrator::explicit_backend_override(),
                    std::slice::from_ref(&chunk),
                )?;
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
pub mod testing {
    pub use crate::daemon::trust::testing::{
        ensure_private_socket_dir, remove_stale_socket_if_trusted,
    };
}
