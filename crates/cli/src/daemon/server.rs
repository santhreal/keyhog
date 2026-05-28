//! Daemon server: long-lived process that holds a compiled scanner
//! and serves scan requests over a Unix socket.

use crate::daemon::frame;
use crate::daemon::protocol::{Request, Response, WIRE_VERSION};
use anyhow::{Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec};
use keyhog_scanner::CompiledScanner;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Notify, Semaphore};

const KEYHOG_VERSION: &str = env!("CARGO_PKG_VERSION");

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
    let cache = dirs::cache_dir().unwrap_or_else(std::env::temp_dir);
    let mut p = cache;
    p.push("keyhog");
    p.push("server.sock");
    p
}

struct ServerState {
    scanner: Arc<CompiledScanner>,
    started_at: Instant,
    scans_served: AtomicU64,
    active_scans: AtomicU32,
    shutdown: Arc<Notify>,
    detector_count: usize,
    // Serializes the read+drain+reset of the process-global
    // `keyhog_scanner::telemetry` counters across concurrent daemon
    // connections. See the scan_text / scan_path drain block for the
    // race scenario.
    telemetry_drain: Arc<Mutex<()>>,
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
    fn new(scanner: CompiledScanner, shutdown: Arc<Notify>, detector_count: usize) -> Self {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let max_conns = (cores * 4).clamp(8, 256);
        Self {
            scanner: Arc::new(scanner),
            started_at: Instant::now(),
            scans_served: AtomicU64::new(0),
            active_scans: AtomicU32::new(0),
            shutdown,
            detector_count,
            telemetry_drain: Arc::new(Mutex::new(())),
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
    let scanner = CompiledScanner::compile(detectors)
        .context("daemon: compiling scanner from detector specs")?;

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

    // Remove a stale socket file from a previous crashed instance.
    // If the file exists AND a daemon is still listening on it, the
    // bind below will fail loudly - we don't unlink blindly.
    if socket_path.exists() {
        match std::os::unix::net::UnixStream::connect(&socket_path) {
            Ok(_) => anyhow::bail!(
                "daemon: socket {} is already bound by another keyhog daemon (refuse to clobber). \
                 Run `keyhog daemon stop` first, or pass --socket to use a different path.",
                socket_path.display()
            ),
            Err(_) => {
                tracing::warn!(
                    socket = %socket_path.display(),
                    "removing stale daemon socket (no listener on the other end)"
                );
                let _ = std::fs::remove_file(&socket_path);
            }
        }
    }

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating daemon socket parent dir {}", parent.display()))?;
    }

    let listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("daemon: binding Unix socket at {}", socket_path.display()))?;

    // 0600 = user-only. Without this the socket inherits the umask
    // default which on most distros is 0644 - a co-tenant user on
    // the same box could connect and request scans, exposing every
    // credential the scanner finds via its responses.
    set_socket_mode_user_only(&socket_path)?;

    let shutdown = Arc::new(Notify::new());
    let state = Arc::new(ServerState::new(scanner, shutdown.clone(), detector_count));

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
                            tracing::error!("daemon: listener accept failed: {e}");
                            break;
                        }
                    }
                }
            }
        }
    });

    shutdown.notified().await;
    let _ = accept_task.await;
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

#[cfg(unix)]
fn set_socket_mode_user_only(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)?;
    let mut perms = meta.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("daemon: chmod 0600 on socket {}", path.display()))
}

#[cfg(not(unix))]
fn set_socket_mode_user_only(_path: &Path) -> Result<()> {
    Ok(())
}

async fn handle_connection(state: Arc<ServerState>, mut stream: UnixStream) -> Result<()> {
    let (reader, writer) = stream.split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut writer = tokio::io::BufWriter::new(writer);

    while let Some(request) = frame::read_request(&mut reader).await? {
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
    let chunk_path = path.clone();
    let drain_lock = state.telemetry_drain.clone();
    // Hand the actual scan to a blocking thread - `scanner.scan` is
    // CPU-heavy and not async-aware. Without `spawn_blocking` a
    // large scan would stall the tokio reactor and block every
    // other connection's framing reads.
    let res = tokio::task::spawn_blocking(move || {
        let chunk = Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "daemon/scan_text".into(),
                path: chunk_path,
                ..Default::default()
            },
        };
        let matches = scanner.scan(&chunk);
        // Drain telemetry alongside the matches so the client can
        // merge per-scan counts into its own process-local counters
        // (telemetry lives in a OnceLock and doesn't cross the IPC
        // boundary on its own). The lock serializes count+drain+reset
        // across concurrent daemon connections - see ServerState
        // .telemetry_drain for the race scenario.
        let _drain = drain_lock.lock().unwrap_or_else(|e| e.into_inner());
        let engine_example_suppressions =
            keyhog_scanner::telemetry::example_suppression_count() as u64;
        let dogfood_events = keyhog_scanner::telemetry::drain_events();
        keyhog_scanner::telemetry::reset_example_suppression_count();
        (matches, engine_example_suppressions, dogfood_events)
    })
    .await;
    state.active_scans.fetch_sub(1, Ordering::Relaxed);
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok((matches, engine_example_suppressions, dogfood_events)) => Response::ScanResults {
            path,
            matches,
            engine_example_suppressions,
            dogfood_events,
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
    let resolved_owned = resolved.clone();
    let drain_lock = state.telemetry_drain.clone();
    type ScanOutput = (
        Vec<keyhog_core::RawMatch>,
        u64,
        Vec<keyhog_scanner::telemetry::DogfoodEvent>,
    );
    let res = tokio::task::spawn_blocking(move || -> Result<ScanOutput> {
        let bytes = std::fs::read(&resolved_owned)
            .with_context(|| format!("daemon: reading {}", resolved_owned.display()))?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let chunk = Chunk {
            data: text.into(),
            metadata: ChunkMetadata {
                source_type: "daemon/scan_path".into(),
                path: Some(resolved_owned.to_string_lossy().into_owned()),
                ..Default::default()
            },
        };
        let matches = scanner.scan(&chunk);
        // See scan_text for the rationale on this drain lock.
        let _drain = drain_lock.lock().unwrap_or_else(|e| e.into_inner());
        let engine_example_suppressions =
            keyhog_scanner::telemetry::example_suppression_count() as u64;
        let dogfood_events = keyhog_scanner::telemetry::drain_events();
        keyhog_scanner::telemetry::reset_example_suppression_count();
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
