//! Daemon server: long-lived process that holds a compiled scanner
//! and serves scan requests over a Unix socket.

use crate::daemon::frame;
use crate::daemon::protocol::{Request, Response, WIRE_VERSION};
use anyhow::{Context, Result};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec};
use keyhog_scanner::CompiledScanner;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Notify;

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
    let cache = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
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
}

impl ServerState {
    fn new(scanner: CompiledScanner, shutdown: Arc<Notify>, detector_count: usize) -> Self {
        Self {
            scanner: Arc::new(scanner),
            started_at: Instant::now(),
            scans_served: AtomicU64::new(0),
            active_scans: AtomicU32::new(0),
            shutdown,
            detector_count,
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

    // Remove a stale socket file from a previous crashed instance.
    // If the file exists AND a daemon is still listening on it, the
    // bind below will fail loudly — we don't unlink blindly.
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
    // default which on most distros is 0644 — a co-tenant user on
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
                            tokio::spawn(async move {
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
    // Hand the actual scan to a blocking thread — `scanner.scan` is
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
        scanner.scan(&chunk)
    })
    .await;
    state.active_scans.fetch_sub(1, Ordering::Relaxed);
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok(matches) => Response::ScanResults { path, matches },
        Err(e) => Response::Error {
            message: format!("daemon: scan task panicked or was cancelled: {e}"),
        },
    }
}

async fn scan_path(
    state: &ServerState,
    path: String,
    working_dir: Option<String>,
) -> Response {
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
    let res = tokio::task::spawn_blocking(move || -> Result<Vec<keyhog_core::RawMatch>> {
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
        Ok(scanner.scan(&chunk))
    })
    .await;
    state.active_scans.fetch_sub(1, Ordering::Relaxed);
    state.scans_served.fetch_add(1, Ordering::Relaxed);

    match res {
        Ok(Ok(matches)) => Response::ScanResults {
            path: Some(resolved.to_string_lossy().into_owned()),
            matches,
        },
        Ok(Err(e)) => Response::Error {
            message: format!("daemon: scan_path failed: {e:#}"),
        },
        Err(e) => Response::Error {
            message: format!("daemon: scan task panicked or was cancelled: {e}"),
        },
    }
}
