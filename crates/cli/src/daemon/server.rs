//! Daemon server: long-lived process that holds a compiled scanner
//! and serves scan requests over a Unix socket.

use crate::daemon::frame;
use crate::daemon::protocol::{
    BackendRecoveryStatus, MassScanStats, ProfileStageMeasurement, RecoveredInputRangeStatus,
    Request, RequestProfile, Response, SourceCoverageGaps, WarmBackendStatus, MASS_BATCH_BYTES,
    MASS_BATCH_CHUNKS, WIRE_VERSION,
};
use crate::daemon::trust;
use crate::daemon::warm_identity::WarmBackendReadiness;
use crate::style;
use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, RawMatch, Source};
use keyhog_scanner::{CompiledScanner, ScanBackend};
use std::num::NonZeroUsize;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex, Notify, OwnedMutexGuard, Semaphore};

const KEYHOG_VERSION: &str = env!("CARGO_PKG_VERSION");
static DAEMON_SOURCE_COVERAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const DEFAULT_REQUEST_READ_TIMEOUT_SECS: u64 = 300;
/// Ceiling on one response write. Without it a client that sends a request and
/// never reads the reply parks its handler inside `Sink::flush` forever once the
/// socket send buffer fills, holding its admission permit for the life of the
/// daemon. 60s is far above the time a local peer needs to drain the largest
/// response the wire allows (`MAX_FRAME_BYTES`, 64 MiB) over a Unix socket.
const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// Connections admitted to the control plane while every scan permit is held.
/// `Health` and `Shutdown` must stay answerable when the data plane is
/// saturated, otherwise `keyhog daemon status`/`stop` report the live daemon as
/// absent and an operator has no way to reclaim it.
const CONTROL_PLANE_ADMISSIONS: usize = 8;
/// Read deadline for a control-only connection. The reserved pool is small, so
/// it has to clear itself rather than depend on peers being well behaved.
const CONTROL_PLANE_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// Maximum concurrent guard commit transactions per daemon. A client
/// that opens transactions in a loop cannot hold unbounded memory.
const MAX_GUARD_TRANSACTIONS: usize = 32;
/// Maximum manifest entries (staged files) in a single GuardCommitBegin
/// frame. A client cannot stuff a transaction with millions of entries.
const MAX_GUARD_MANIFEST_ENTRIES: usize = 100_000;
/// How long `Shutdown` waits for in-flight scans to finish before it
/// acknowledges anyway. The wire contract promises a flush, but an unbounded
/// wait would let one wedged mass transaction make the daemon unstoppable.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

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
        }
    }
}

impl std::error::Error for DaemonServiceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AcceptLoopTask(_) => None,
            Self::ListenerAccept(error) => Some(error),
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

/// Process-atomic allocator for per-request profile identities. The daemon
/// generation string (already advertised in `WarmBackendStatus`) scopes the
/// sequence so ids stay unique across daemon restarts and processes.
struct RequestIdAllocator {
    generation: String,
    sequence: AtomicU64,
}

impl RequestIdAllocator {
    fn new(generation: String) -> Self {
        Self {
            generation,
            sequence: AtomicU64::new(0),
        }
    }

    fn next(&self) -> String {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        format!("{}-{:016x}", self.generation, sequence)
    }
}

/// One isolated profiling runtime for a single profiled daemon request.
/// Created only when the client asked for a profile; the runtime is entered
/// on the blocking scan thread and propagates to scanner rayon workers via
/// `keyhog_profile::current_runtime()`, so concurrent profiled requests never
/// share measurements.
struct RequestProfileCapture {
    request_id: String,
    runtime: keyhog_profile::Runtime,
}

impl RequestProfileCapture {
    fn new(request_id: String) -> Self {
        Self {
            request_id,
            runtime: keyhog_profile::Runtime::new(),
        }
    }

    fn enter(&self) -> keyhog_profile::ContextGuard {
        self.runtime.enter()
    }

    /// Drain the isolated runtime into a bounded, privacy-safe payload. Runs
    /// on the scan thread while its context guard is alive so the stage
    /// counter drain reads this request's runtime, never a peer's.
    fn finish(self, started: Instant) -> RequestProfile {
        let stages = keyhog_profile::take_stage_measurements()
            .into_iter()
            .map(|measurement| ProfileStageMeasurement {
                stage: measurement.stage.as_str().to_string(),
                calls: measurement.calls,
                elapsed_ns: measurement.elapsed_ns,
            })
            .collect();
        // Span records stay daemon-side; only their exact loss count crosses.
        let (_spans, dropped_span_events) = self.runtime.take_session_span_records();
        let (_point_events, _annotations, event_loss) = self.runtime.take_session_typed_events();
        RequestProfile {
            request_id: self.request_id,
            wall_time_ns: u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX), // LAW10: profiling duration saturates when nanoseconds exceed u64; scan findings and errors are unchanged.
            stages,
            dropped_span_events,
            dropped_point_events: event_loss.point_events,
            dropped_annotations: event_loss.annotations,
            sampled_out_events: event_loss.sampled_out_events,
        }
    }
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
    // Per-request profile identity: the daemon generation string (the same one
    // `WarmBackendStatus` advertises) plus a process-atomic sequence, so every
    // profiled scan request is attributable to exactly one response.
    request_identity: RequestIdAllocator,
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
    // Admission reserved for connections that arrive while every data-plane
    // permit is held. They serve Hello/Health/Shutdown and refuse scan work, so
    // an operator can always observe and stop a saturated daemon.
    control_limit: Arc<Semaphore>,
    // Set by `Shutdown` before it waits for in-flight scans. New scan and mass
    // requests are refused while it is set, so the drain terminates.
    draining: AtomicBool,
    // Notified when in-flight work reaches zero, so the drain does not poll.
    scans_drained: Notify,
    // Work requests currently between dispatch and a written response. Separate
    // from `active_scans`, which covers scanner execution only.
    active_requests: AtomicU32,
    /// Guard runtime: root registry, attestation index, policy identity.
    guard: Arc<crate::daemon::guard_runtime::GuardRuntime>,
    /// Guard filesystem watcher: native watchers for all guard roots.
    /// Guard scan filter: finalizes raw matches through the same
    /// suppression/allowlist/confidence pipeline as `keyhog scan`.
    guard_filter: Arc<crate::orchestrator::DefaultScanFilter>,
    guard_watcher: Arc<parking_lot::Mutex<crate::daemon::guard_watcher::GuardWatcher>>,
    /// Durable guard store for crash recovery. None when no store path is configured.
    guard_store: Option<Arc<keyhog_core::guard_store::DurableGuardStore>>,
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
        guard_hot_index_budget: Option<usize>,
        guard_filter: crate::orchestrator::DefaultScanFilter,
        guard_recon_config: keyhog_sources::guard::GuardReconciliationConfig,
        guard_store: Option<Arc<keyhog_core::guard_store::DurableGuardStore>>,
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
            request_identity: RequestIdAllocator::new(warm_backend.daemon_generation().to_string()),
            warm_backend,
            mass_service: options.mass_service,
            mass_gpu_primary_required: options.mass_gpu_primary_required,
            fragment_scan_lock: Arc::new(Mutex::new(())),
            connection_limit: Arc::new(Semaphore::new(max_conns)),
            control_limit: Arc::new(Semaphore::new(CONTROL_PLANE_ADMISSIONS)),
            draining: AtomicBool::new(false),
            scans_drained: Notify::new(),
            active_requests: AtomicU32::new(0),
            guard: Arc::new(match guard_hot_index_budget {
                Some(budget) => crate::daemon::guard_runtime::GuardRuntime::with_hot_index_budget(budget),
                None => crate::daemon::guard_runtime::GuardRuntime::new(),
            }),
            guard_filter: Arc::new(guard_filter),
            guard_watcher: Arc::new(parking_lot::Mutex::new(
                crate::daemon::guard_watcher::GuardWatcher::new(
                    guard_recon_config,
                )
                .unwrap_or_else(|e| {
                    tracing::warn!("daemon: guard watcher disabled: {}", e);
                    crate::daemon::guard_watcher::GuardWatcher::new_disabled()
                }),
            )),
            guard_store,
        }
    }

    fn begin_scan(&self) {
        self.active_scans.fetch_add(1, Ordering::AcqRel);
    }

    /// Release one scan slot and wake a waiting drain when the daemon just went
    /// idle. `Shutdown` blocks on this instead of polling.
    fn finish_scan(&self) {
        if self.active_scans.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.scans_drained.notify_waiters();
        }
    }

    /// Claim one in-flight work request, covering dispatch AND the response
    /// write. Draining on scan execution alone is not enough: `active_scans`
    /// drops to zero as soon as the scanner returns, so a shutdown that waited
    /// only on that acknowledged while the results frame was still unflushed and
    /// the client saw a closed socket instead of its findings.
    fn begin_request(&self) {
        self.active_requests.fetch_add(1, Ordering::AcqRel);
    }

    fn finish_request(&self) {
        if self.active_requests.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.scans_drained.notify_waiters();
        }
    }

    fn is_draining(&self) -> bool {
        self.draining.load(Ordering::Acquire)
    }

    /// Refuse new work, then wait for in-flight work to finish executing and to
    /// have its response written. Returns what was still outstanding when the
    /// wait gave up, so the operator learns the flush the wire contract promises
    /// did not complete.
    ///
    /// One request can be read microseconds before `draining` is set and land in
    /// the window before it claims its slot. That request is refused or its
    /// connection is closed, which is the same outcome it would have had by
    /// arriving a moment later.
    async fn drain_active_work(&self, timeout: Duration) -> u32 {
        self.draining.store(true, Ordering::Release);
        let deadline = Instant::now() + timeout;
        loop {
            // `enable()` registers the waiter now. `notify_waiters` only wakes
            // waiters already queued, so registering after the counter loads
            // would miss the very completion this drain is waiting for.
            let mut idle = std::pin::pin!(self.scans_drained.notified());
            idle.as_mut().enable();
            let outstanding = self.outstanding_work();
            if outstanding == 0 {
                return 0;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return outstanding;
            };
            if tokio::time::timeout(remaining, idle).await.is_err() {
                return self.outstanding_work();
            }
        }
    }

    fn outstanding_work(&self) -> u32 {
        self.active_scans
            .load(Ordering::Acquire)
            .saturating_add(self.active_requests.load(Ordering::Acquire))
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

/// Restore `SIG_IGN` for `SIGPIPE` in the daemon service process.
///
/// `main::reset_sigpipe` sets `SIGPIPE` back to `SIG_DFL` so `keyhog scan | head`
/// dies quietly like every other Unix filter. That disposition is process-wide,
/// and a server is the one KeyHog process it is wrong for: when a client
/// abandons a connection while the daemon is writing the reply, the `write(2)`
/// raises `SIGPIPE` and the kernel kills the whole daemon. One client that reads
/// part of a large `ScanResults` frame and closes therefore terminates the warm
/// scanner for every other client, with no diagnostic and a stale socket file
/// left behind. Serving code wants the library default: `write` returns `EPIPE`,
/// the connection handler logs it, and the process keeps serving.
fn ignore_sigpipe_while_serving() {
    // SAFETY: `signal(2)` with `SIG_IGN` is defined for `SIGPIPE` and is called
    // once, from the daemon service entry point, before any connection exists.
    // Restoring the Rust startup default cannot race a handler it removes.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

pub(crate) async fn run_with_backend_override(
    socket_path: PathBuf,
    detectors: Vec<DetectorSpec>,
    detector_rules_digest: String,
    options: ServerOptions,
    backend_override: Option<ScanBackend>,
    guard_hot_index_budget: Option<usize>,
    guard_recon_config: keyhog_sources::guard::GuardReconciliationConfig,
    guard_scanner_idle_timeout: Option<u64>,
    guard_store_path: Option<PathBuf>,
) -> Result<()> {
    ignore_sigpipe_while_serving();
    // Tell the operator the daemon is working before scanner compile and warmup.
    // Duration varies with the detector corpus, backend, cache state, and host.
    // The count is the pre-compile spec count; the ready line reports the final
    // compiled count.
    announce_daemon_starting(detectors.len());
    let guard_filter = crate::orchestrator::DefaultScanFilter::for_guard(&detectors);
    let (scanner, router, detector_count, required_backends) =
        compile_daemon_scan_runtime(detectors, backend_override)?;
    let warm_backend =
        WarmBackendReadiness::capture(&scanner, &detector_rules_digest, required_backends)?;
    let listener = bind_trusted_daemon_socket(&socket_path)?;
    let shutdown = Arc::new(Notify::new());

    // Open the durable guard store if a path is configured. The store
    // persists root records and attestations across daemon restarts.
    // On startup, mark the service as unclean; a clean marker is only
    // written during a graceful shutdown.
    let guard_store: Option<Arc<keyhog_core::guard_store::DurableGuardStore>> = match &guard_store_path {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    tracing::warn!("daemon: failed to create guard store dir {}: {}", parent.display(), e);
                }
            }
            match keyhog_core::guard_store::DurableGuardStore::open(path) {
                Ok(store) => {
                    if let Err(e) = store.mark_unclean_shutdown() {
                        tracing::warn!("daemon: failed to mark guard store unclean: {}", e);
                    }
                    tracing::info!("daemon: guard store opened at {}", path.display());
                    Some(Arc::new(store))
                }
                Err(e) => {
                    tracing::warn!("daemon: failed to open guard store at {}: {}; continuing without durable state", path.display(), e);
                    None
                }
            }
        }
        None => None,
    };

    let state = Arc::new(ServerState::new(
        scanner,
        router,
        shutdown.clone(),
        detector_count,
        detector_rules_digest.clone(),
        options,
        backend_override,
        warm_backend,
        guard_hot_index_budget,
        guard_filter,
        guard_recon_config,
        guard_store,
    ));

    // Set the guard policy identity from the daemon's scanner and build
    // identity. This binds clean attestations to the exact detector corpus,
    // suppression, and configuration the daemon was started with.
    state.guard.set_policy_identity(keyhog_core::guard_state::GuardPolicyIdentity {
        build_identity: KEYHOG_VERSION.to_string(),
        detector_digest: detector_rules_digest.clone(),
        suppression_digest: String::new(),
        keyhogignore_digest: String::new(),
        config_digest: String::new(),
        decode_policy_version: 1,
        source_policy_digest: String::new(),
        guard_schema_version: keyhog_core::guard_state::GUARD_SCHEMA_VERSION,
        report_semantics_version: 1,
    });

    // Apply configured scanner idle timeout to the guard runtime.
    if let Some(secs) = guard_scanner_idle_timeout {
        state.guard.set_scanner_idle_timeout(secs);
    }

    announce_daemon_ready(&socket_path, detector_count, &state.warm_backend_status());
    let accept_task = spawn_accept_loop(listener, state.clone());
    let watcher_task = spawn_guard_watcher_loop(state.clone());

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
        backend_override,
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

/// Spawn a background task that polls the guard filesystem watcher and
/// processes events through the guard state machine. Events are
/// coalesced within a short window before applying transitions.
fn spawn_guard_watcher_loop(state: Arc<ServerState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let coalesce_window = std::time::Duration::from_millis(
            state.guard_watcher.lock().coalesce_window_ms(),
        );
        loop {
            tokio::select! {
                _ = state.shutdown.notified() => return,
                _ = tokio::time::sleep(coalesce_window) => {
                    let events = state.guard_watcher.lock().poll_events();
                    for (root, evts) in events {
                        process_guard_events(&state, &root, evts);
                    }
                    // Sweep abandoned transactions each cycle.
                    state.guard.sweep_stale_transactions();
                }
            }
        }
    })
}

/// Process a batch of guard events for one root. Advisory filesystem
/// events mark the root dirty (EventAccepted) only when it is in a
/// state that accepts that transition (Current or Blocked). Overflow
/// (ReconcileSubtree) uses CoverageLost, which is legal from every
/// active state. Events on roots in the Indexing state are recorded
/// via `mark_dirty_during_indexing` so the baseline handler can
/// transition the root to Dirty after the scan completes instead of
/// claiming Current. Events on Dirty, Degraded, StalePolicy, and
/// Stopped roots are no-ops: those states already account for
/// unscanned changes.
fn process_guard_events(state: &ServerState, root: &Path, events: Vec<keyhog_sources::guard::GuardEvent>) {
    use keyhog_core::guard_state::{GuardRootState, GuardTransition};
    use keyhog_sources::guard::GuardEvent;

    let root_bytes = std::os::unix::ffi::OsStrExt::as_bytes(root.as_os_str());
    let has_overflow = events.iter().any(|e| matches!(e, GuardEvent::ReconcileSubtree(_)));

    let current_state = state.guard.root_state(root_bytes);
    let transition = if has_overflow {
        // CoverageLost is legal from Indexing, Current, Dirty, Blocked,
        // and Degraded. Stopped roots are not active, so skip.
        match current_state {
            Some(GuardRootState::Stopped) | None => return,
            Some(GuardRootState::Indexing) => {
                // Overflow during indexing: mark for re-scan and
                // also apply CoverageLost to signal degraded coverage.
                state.guard.mark_dirty_during_indexing(root_bytes);
                Some(GuardTransition::CoverageLost)
            }
            _ => Some(GuardTransition::CoverageLost),
        }
    } else {
        // EventAccepted is legal only from Current and Blocked.
        match current_state {
            Some(GuardRootState::Current) | Some(GuardRootState::Blocked) => {
                Some(GuardTransition::EventAccepted)
            }
            Some(GuardRootState::Indexing) => {
                // Events during indexing: the baseline scan is in
                // progress. Record that changes were observed so the
                // baseline handler can transition to Dirty instead
                // of Current after the scan completes.
                state.guard.mark_dirty_during_indexing(root_bytes);
                None
            }
            _ => None,
        }
    };

    if let Some(transition) = transition {
        match state.guard.transition_root(root_bytes, &transition) {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    "daemon: guard transition failed for {}: {}",
                    root.display(),
                    e
                );
            }
        }
    }
}

/// Check whether a path is a system directory that should never be
/// registered as a guard root. Prevents a same-user client from
/// making the daemon scan sensitive OS paths.
fn is_system_path(path: &std::path::Path) -> bool {
    const SYSTEM_PREFIXES: &[&str] = &[
        "/etc", "/proc", "/sys", "/dev", "/boot", "/run", "/var/log",
        "/usr", "/bin", "/sbin", "/lib", "/lib64",
    ];
    let path_str = path.to_string_lossy();
    SYSTEM_PREFIXES.iter().any(|prefix| {
        path_str.as_ref() == *prefix || path_str.starts_with(&format!("{}/", prefix))
    })
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
                    Ok((stream, _addr)) => spawn_connection_handler(state.clone(), stream),
                    Err(e) => {
                        handle_accept_error(&state.shutdown, e).await?;
                    }
                }
            }
        }
    }
}

/// Admission class of one accepted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    /// Holds a data-plane permit: scan and mass requests are served.
    Scan,
    /// The data plane was saturated when this connection arrived. Hello, Health,
    /// and Shutdown are served; scan and mass requests are refused.
    ControlOnly,
}

fn spawn_connection_handler(state: Arc<ServerState>, stream: UnixStream) {
    // Never wait for a data-plane permit here. The accept loop is the only task
    // that can hand a connection to a handler, so awaiting a permit that a slow
    // or non-reading client holds stops the daemon from answering Health and
    // Shutdown at all: `keyhog daemon status`/`stop` then time out on the
    // handshake and report the live daemon as absent (KH-551).
    let (permit, admission) = match state.connection_limit.clone().try_acquire_owned() {
        Ok(permit) => (permit, Admission::Scan),
        Err(_) => match state.control_limit.clone().try_acquire_owned() {
            // LAW10: exhausted scan admission intentionally reserves the separate control pool; no scan runs on the control permit.
            Ok(permit) => (permit, Admission::ControlOnly),
            // Both pools exhausted: drop the socket now rather than queue
            // unbounded work. The client observes EOF on its handshake read.
            Err(_) => {
                // LAW10: exhausted admission is surfaced by the warning below and EOF to the client; no request is executed.
                tracing::warn!(
                    "daemon: refused a connection; every scan and control admission is held"
                );
                return;
            }
        },
    };
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = handle_connection(state, stream, admission).await {
            tracing::warn!("daemon: connection ended with error: {e:#}");
        }
    });
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
                // LAW10: poisoned coverage lock => fail closed with an explicit daemon error response.
                let _ = sender.blocking_send(MassFilesystemMessage::Error(
                    // LAW10: unused-binding marker; a dropped receiver leaves no consumer, so send status has no runtime effect and is not a fallback.
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
        let _ = sender.blocking_send(MassFilesystemMessage::Complete(gaps)); // LAW10: unused-binding marker; a dropped receiver leaves no consumer, so send status has no runtime effect and is not a fallback.
    });
    receiver
}

struct MassSession {
    state: Arc<ServerState>,
    dogfood: bool,
    profile: bool,
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

async fn handle_connection(
    state: Arc<ServerState>,
    stream: UnixStream,
    admission: Admission,
) -> Result<()> {
    trust::verify_accepted_peer(&stream)?;
    let mut transport = frame::server_transport(stream);
    // A control-only connection exists because the data plane was full, so it
    // must not be squattable. The reserved pool is small, and inheriting the
    // 300s request budget would let eight idle peers wedge Health and Shutdown
    // for five minutes: the exact outcome the reservation exists to prevent.
    // Five seconds matches the client's own control response deadline, and a
    // real control client sends Hello immediately.
    let read_timeout = match admission {
        Admission::Scan => state.request_read_timeout,
        Admission::ControlOnly => CONTROL_PLANE_READ_TIMEOUT,
    };
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
                send_response(
                    &mut transport,
                    Response::Error {
                        message: "daemon: first request on a connection must be Hello \
                             (wire and corpus identity handshake required before scan or shutdown)"
                            .to_string(),
                    },
                )
                .await?;
                break;
            }
            hello_ok = true;
        }

        if let Some(refusal) = admission_refusal(&state, admission, &request) {
            send_response(&mut transport, refusal).await?;
            continue;
        }

        // Claim the slot before dispatch and hold it until the response is
        // written, so a shutdown drain flushes results rather than racing them.
        let work_slot = is_work_request(&request).then(|| RequestSlot::claim(&state));
        let response = match request {
            Request::MassBegin { dogfood, profile } => {
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
                    state.begin_scan();
                    mass_session = Some(MassSession {
                        state: state.clone(),
                        dogfood,
                        profile,
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
                    let batch =
                        scan_mass_batch(&state, chunks, session.dogfood, session.profile).await;
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
                            let batch =
                                scan_mass_batch(&state, chunks, session.dogfood, session.profile)
                                    .await;
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
            other @ (Request::ScanText { .. }
                | Request::ScanPath { .. }
                | Request::GuardCommitBegin { .. }
                | Request::GuardCommitBlob { .. }
                | Request::GuardCommitFinish { .. }
                | Request::GuardAdd { .. }
                | Request::GuardReconcile { .. }) => {
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
        let sent = send_response(&mut transport, response).await;
        // Released only now: the slot covers delivery, not just execution.
        drop(work_slot);
        sent?;
        if is_shutdown_ack {
            state.shutdown.notify_waiters();
            break;
        }
    }
    Ok(())
}

/// Requests that do scanner work, as opposed to the always-answerable control
/// requests (`Hello`, `Health`, `Shutdown`).
fn is_work_request(request: &Request) -> bool {
    matches!(
        request,
        Request::ScanText { .. }
            | Request::ScanPath { .. }
            | Request::MassBegin { .. }
            | Request::MassBatch { .. }
            | Request::MassFilesystemBegin { .. }
            | Request::MassFilesystemNext
            | Request::MassEnd
            | Request::GuardCommitBegin { .. }
            | Request::GuardCommitBlob { .. }
            | Request::GuardCommitFinish { .. }
            | Request::GuardAdd { .. }
            | Request::GuardReconcile { .. }
    )
}

/// RAII claim on one in-flight work request. Releasing it is what tells a
/// shutdown drain the request has both executed and been written to its client.
struct RequestSlot<'state> {
    state: &'state ServerState,
}

impl<'state> RequestSlot<'state> {
    fn claim(state: &'state ServerState) -> Self {
        state.begin_request();
        Self { state }
    }
}

impl Drop for RequestSlot<'_> {
    fn drop(&mut self) {
        self.state.finish_request();
    }
}

/// Write one response with a ceiling on the flush.
///
/// `Sink::send` flushes, so a peer that stops reading parks this handler inside
/// the write once the socket buffer fills. Untimed, that permanently consumes
/// the connection's admission permit; the timeout turns it into a closed
/// connection and a released slot.
async fn send_response(transport: &mut frame::ServerTransport, response: Response) -> Result<()> {
    let kind = crate::daemon::protocol::response_kind(&response);
    match tokio::time::timeout(RESPONSE_WRITE_TIMEOUT, transport.send(response)).await {
        Ok(result) => result,
        Err(_elapsed) => anyhow::bail!(
            "daemon: peer did not read the {} response within {}s; \
             closing the connection to reclaim its admission slot",
            kind,
            RESPONSE_WRITE_TIMEOUT.as_secs()
        ),
    }
}

/// Refuse work this connection is not admitted to run, or that the daemon has
/// stopped accepting because it is draining for shutdown. `Hello`, `Health`, and
/// `Shutdown` are always answered: they are how an operator observes and
/// reclaims a saturated or stopping daemon.
fn admission_refusal(
    state: &ServerState,
    admission: Admission,
    request: &Request,
) -> Option<Response> {
    if !is_work_request(request) {
        return None;
    }
    if admission == Admission::ControlOnly {
        return Some(Response::Error {
            message: format!(
                "daemon: at scan capacity, so this connection was admitted for control requests \
                 only ({} refused). Retry, or scan in process with `--daemon=off`.",
                crate::daemon::protocol::request_kind(request)
            ),
        });
    }
    // MassEnd stays legal while draining: it is how an in-flight transaction
    // finishes, and the drain is waiting for exactly that.
    if state.is_draining() && !matches!(request, Request::MassEnd) {
        return Some(Response::Error {
            message: format!(
                "daemon: draining for shutdown, so no new scan work is accepted ({} refused). \
                 Start a new daemon or scan in process with `--daemon=off`.",
                crate::daemon::protocol::request_kind(request)
            ),
        });
    }
    None
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
                guard_roots_registered: state.guard.root_count() as u64,
                guard_roots_current: state.guard.count_by_state(keyhog_core::guard_state::GuardRootState::Current) as u64,
                guard_roots_blocked: state.guard.count_by_state(keyhog_core::guard_state::GuardRootState::Blocked) as u64,
                guard_roots_degraded: state.guard.count_by_state(keyhog_core::guard_state::GuardRootState::Degraded) as u64,
                guard_active_transactions: state.guard.active_transaction_count() as u64,
                warm_backend: state.warm_backend_status(),
            },
            Err(_) => Response::Error {
                // LAW10: poisoned health state => fail closed through the operator-visible response.
                message: "daemon: backend-recovery health lock is poisoned; restart the daemon"
                    .to_string(),
            },
        },
        Request::ScanText {
            path,
            text,
            dogfood,
            profile,
        } => scan_text(state, path, text, dogfood, profile).await,
        Request::ScanPath {
            path,
            working_dir,
            dogfood,
            profile,
        } => scan_path(state, path, working_dir, dogfood, profile).await,
        Request::MassBegin { .. }
        | Request::MassBatch { .. }
        | Request::MassFilesystemBegin { .. }
        | Request::MassFilesystemNext
        | Request::MassEnd => Response::Error {
            message: "daemon: mass transaction request reached invalid dispatch state".to_string(),
        },
        Request::GuardCommitBegin {
            repo_path,
            index_fingerprint,
            hash_algorithm,
            entries,
        } => {
            // Bound concurrent transactions and manifest entries to
            // prevent a client from holding unbounded daemon memory.
            if state.guard.active_transaction_count() >= MAX_GUARD_TRANSACTIONS {
                return Response::Error {
                    message: format!(
                        "daemon: guard commit: too many concurrent transactions (max {})",
                        MAX_GUARD_TRANSACTIONS
                    ),
                };
            }
            if entries.len() > MAX_GUARD_MANIFEST_ENTRIES {
                return Response::Error {
                    message: format!(
                        "daemon: guard commit: manifest has {} entries, max is {}",
                        entries.len(),
                        MAX_GUARD_MANIFEST_ENTRIES
                    ),
                };
            }
            // Parse the hash algorithm.
            let git_hash = match hash_algorithm.as_str() {
                "sha1" => keyhog_core::guard_state::GitHashAlgorithm::Sha1,
                "sha256" => keyhog_core::guard_state::GitHashAlgorithm::Sha256,
                other => {
                    return Response::Error {
                        message: format!("daemon: guard commit: unsupported hash algorithm '{}'", other),
                    };
                }
            };
            // Get the policy identity for attestation lookup.
            let identity = match state.guard.policy_identity() {
                Some(id) => id,
                None => {
                    return Response::Error {
                        message: "daemon: guard commit: policy identity not yet established".to_string(),
                    };
                }
            };
            let policy_short = match identity.short_digest() {
                Ok(d) => d,
                Err(e) => {
                    return Response::Error {
                        message: format!("daemon: guard commit: policy digest error: {}", e),
                    };
                }
            };
            // Classify entries: skip deletions/symlinks/submodules,
            // look up file blobs in the clean attestation cache.
            // Deduplicate by OID: two staged paths with identical
            // content share one Git blob OID and need only one scan.
            let mut clean_hits: Vec<String> = Vec::new();
            let mut required_blob_oids: Vec<String> = Vec::new();
            let mut seen_oids: std::collections::HashSet<String> = std::collections::HashSet::new();
            let mut objects_skipped = 0u64;
            let mut bytes_requested = 0u64;
            let mut bytes_hit = 0u64;
            for entry in &entries {
                if entry.kind != "file" {
                    objects_skipped += 1;
                    continue;
                }
                if entry.object_oid.is_empty() {
                    objects_skipped += 1;
                    continue;
                }
                if !seen_oids.insert(entry.object_oid.clone()) {
                    // Duplicate OID: identical content is scanned
                    // once, so its bytes are accounted once too
                    // (conservation).
                    continue;
                }
                bytes_requested += entry.object_size;
                if let Some(_att) = state.guard.lookup_attestation(
                    git_hash,
                    &entry.object_oid,
                    &policy_short,
                ) {
                    clean_hits.push(entry.object_oid.clone());
                    bytes_hit += entry.object_size;
                } else {
                    required_blob_oids.push(entry.object_oid.clone());
                }
            }
            let txn_id = state.guard.next_transaction_id();
            let txn = crate::daemon::guard_runtime::GuardTransaction {
                transaction_id: txn_id,
                repo_path: repo_path.clone(),
                index_fingerprint: index_fingerprint.clone(),
                hash_algorithm: git_hash,
                clean_hits: clean_hits.clone(),
                required_blob_oids: required_blob_oids.clone(),
                scanned_oids: Vec::new(),
                bytes_scanned: 0,
                bytes_requested,
                bytes_hit,
                findings_count: 0,
                coverage_gaps: 0,
                objects_skipped,
                started_at: Instant::now(),
                policy_short_digest: policy_short,
            };
            state.guard.begin_transaction(txn);
            Response::GuardCommitPlan {
                transaction_id: txn_id,
                clean_hits,
                required_blob_oids,
                max_blob_bytes: 8 * 1024 * 1024,
            }
        }
        Request::GuardCommitBlob {
            transaction_id,
            blob_oid,
            object_size,
            payload,
        } => {
            // Verify the transaction exists and this blob is expected.
            let txn = match state.guard.get_transaction(transaction_id) {
                Some(t) => t,
                None => {
                    return Response::Error {
                        message: format!("daemon: guard commit blob: transaction {} not found", transaction_id),
                    };
                }
            };
            if !txn.required_blob_oids.contains(&blob_oid) {
                return Response::Error {
                    message: format!(
                        "daemon: guard commit blob: OID {} not in required set for transaction {}",
                        blob_oid, transaction_id
                    ),
                };
            }
            // Verify the payload matches the declared OID and size.
            // This prevents a client from streaming benign bytes
            // labeled with a secret-bearing blob's OID.
            let payload_bytes: Vec<u8> = payload
                .iter()
                .flat_map(|c| c.data.as_bytes().iter().copied())
                .collect();
            if payload_bytes.len() as u64 != object_size {
                return Response::Error {
                    message: format!(
                        "daemon: guard commit blob: size mismatch for {}: declared {}, got {}",
                        blob_oid, object_size, payload_bytes.len()
                    ),
                };
            }
            let computed_oid = compute_git_blob_oid(txn.hash_algorithm, &payload_bytes);
            if computed_oid != blob_oid {
                return Response::Error {
                    message: format!(
                        "daemon: guard commit blob: OID mismatch for {}: declared {}, computed {}",
                        blob_oid, blob_oid, computed_oid
                    ),
                };
            }
            // Scan the blob payload using the existing scanner.
            let scanner = state.scanner.clone();
            let router = state.router.clone();
            let backend_override = state.backend_override;
            let recover_automatic_backend_faults = crate::orchestrator::automatic_backend_recovery_allowed(
                backend_override,
                false,
                keyhog_scanner::gpu::gpu_runtime_policy(),
            );
            let fragment_scan_lock = state.fragment_scan_lock.clone();
            let telemetry = Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
            let txn_id = transaction_id;
            let oid = blob_oid.clone();
            let _fragment_guard = fragment_scan_lock.lock_owned().await;
            scanner.clear_fragment_cache();
            let bytes_scanned: u64 = payload.iter().map(|c| c.data.len() as u64).sum();
            let scan_result = tokio::task::spawn_blocking(move || -> Result<Vec<RawMatch>> {
                let matches = keyhog_scanner::telemetry::with_scan_telemetry(
                    &telemetry,
                    || -> Result<Vec<RawMatch>> {
                        scanner.clear_fragment_cache();
                        let total_bytes: usize = payload.iter().map(|c| c.data.len()).sum();
                        keyhog_profile::add_input_units(1);
                        keyhog_profile::add_input_bytes(total_bytes as u64);
                        if payload.is_empty() {
                            scanner.clear_fragment_cache();
                            return Ok(Vec::new());
                        }
                        let selection = router.choose_with_plan(
                            scanner.as_ref(),
                            backend_override,
                            &payload,
                        )?;
                        let outcome = crate::orchestrator::scan_selected_batch(
                            scanner.as_ref(),
                            &payload,
                            selection.backend,
                            selection.phase1_plan.as_ref(),
                            selection.execution_route,
                            selection
                                .recovery_plan
                                .filter(|_| recover_automatic_backend_faults),
                        )
                        .with_context(|| {
                            format!(
                                "selected backend {} failed during guard blob scan",
                                selection.backend.label()
                            )
                        })?;
                        let raw: Vec<RawMatch> =
                            outcome.per_chunk.into_iter().flatten().collect();
                        Ok(raw)
                    },
                )?;
                Ok(matches)
            })
            .await;
            let raw_matches = match scan_result {
                Ok(Ok(matches)) => matches,
                Ok(Err(e)) => {
                    // Scan failed: record as coverage gap so the
                    // transaction terminates as Degraded, not Current.
                    if let Err(msg) = state.guard.record_coverage_gap(txn_id, &oid, object_size) {
                        return Response::Error { message: msg };
                    }
                    return Response::Error {
                        message: format!("daemon: guard commit blob: scan failed for {}: {}", oid, e),
                    };
                }
                Err(e) => {
                    return Response::Error {
                        message: format!("daemon: guard commit blob: task panicked for {}: {}", oid, e),
                    };
                }
            };
            // Finalize raw matches through the suppression pipeline
            // (allowlist, test-fixture, confidence, inline suppression)
            // so suppressed/example values do not count as findings.
            // If finalization fails, treat it as a coverage gap
            // rather than zero findings (fail closed).
            let (findings, coverage_gap) = match state.guard_filter.finalize_count(&state.scanner, raw_matches) {
                Some(count) => (count as u64, false),
                None => (0, true),
            };
            if coverage_gap {
                // Finalization failed: record the blob as scanned
                // (for conservation) but with a coverage gap so the
                // terminal state is Degraded, not Current.
                if let Err(msg) = state.guard.record_coverage_gap(txn_id, &oid, bytes_scanned) {
                    return Response::Error { message: msg };
                }
            } else {
                if let Err(msg) = state.guard.record_scanned_blob(txn_id, &oid, bytes_scanned, findings) {
                    return Response::Error { message: msg };
                }
                if findings == 0 {
                    // If clean (zero findings), insert attestation for reuse.
                    let identity = state.guard.policy_identity();
                    if let Some(id) = identity {
                        let att = keyhog_core::guard_state::GitCleanAttestation {
                            hash_algorithm: txn.hash_algorithm,
                            blob_oid: oid.clone(),
                            object_size,
                            policy_identity: id,
                            last_seen_sequence: 0,
                        };
                        state.guard.insert_attestation(att);
                    }
                }
            }
            // Acknowledge the blob was scanned with a dedicated ack
            // frame, not a synthetic plan with empty lists.
            Response::GuardCommitBlobAck {
                transaction_id: txn_id,
                blob_oid: oid,
                bytes_scanned,
                findings_count: findings,
            }
        }
        Request::GuardCommitFinish {
            transaction_id,
            client_objects_streamed,
            client_bytes_streamed,
        } => {
            // Validate before removing the transaction so a failed
            // check does not discard the scanning work. The client
            // can retry or correct and re-send Finish.
            let txn = match state.guard.get_transaction(transaction_id) {
                Some(t) => t,
                None => {
                    return Response::Error {
                        message: format!("daemon: guard commit finish: transaction {} not found", transaction_id),
                    };
                }
            };
            // Validate conservation: the server must have actually
            // scanned every required blob. The client-supplied count
            // is a cross-check, not the primary authority.
            let required_count = txn.required_blob_oids.len() as u64;
            let server_scanned = txn.scanned_oids.len() as u64;
            if server_scanned != required_count {
                return Response::Error {
                    message: format!(
                        "daemon: guard commit: server scanned {} of {} required blobs",
                        server_scanned, required_count
                    ),
                };
            }
            if client_objects_streamed != required_count {
                return Response::Error {
                    message: format!(
                        "daemon: guard commit: client streamed {} but required {}",
                        client_objects_streamed, required_count
                    ),
                };
            }
            // Revalidate the staged index fingerprint. If the index
            // changed between Begin and Finish, the scanned content
            // may not match what is now staged, so refuse the receipt.
            let repo_path = std::path::PathBuf::from(&txn.repo_path);
            if !keyhog_sources::verify_staged_fingerprint(&repo_path, &txn.index_fingerprint) {
                return Response::Error {
                    message: format!(
                        "daemon: guard commit finish: index fingerprint mismatch for {}; the staged content changed during the transaction",
                        txn.repo_path
                    ),
                };
            }
            // All validation passed. Remove the transaction from
            // the in-flight map.
            let _ = state.guard.finish_transaction(transaction_id);
            let total_objects = txn.clean_hits.len() as u64 + txn.scanned_oids.len() as u64 + txn.objects_skipped;
            let objects_hit = txn.clean_hits.len() as u64;
            let objects_scanned = txn.scanned_oids.len() as u64;
            let bytes_hit = txn.bytes_hit;
            let terminal_state = if txn.findings_count > 0 {
                keyhog_core::guard_state::GuardRootState::Blocked
            } else if txn.coverage_gaps > 0 {
                keyhog_core::guard_state::GuardRootState::Degraded
            } else {
                keyhog_core::guard_state::GuardRootState::Current
            };
            let identity = state.guard.policy_identity();
            let receipt = keyhog_core::guard_state::GuardReceipt {
                objects_requested: total_objects,
                objects_hit,
                objects_scanned,
                objects_skipped: txn.objects_skipped,
                bytes_requested: txn.bytes_requested,
                bytes_hit,
                bytes_scanned: txn.bytes_scanned,
                findings_count: txn.findings_count,
                coverage_gaps: txn.coverage_gaps,
                terminal_state,
                policy_identity: identity.clone().unwrap_or_else(|| keyhog_core::guard_state::GuardPolicyIdentity {
                    build_identity: String::new(),
                    detector_digest: String::new(),
                    suppression_digest: String::new(),
                    keyhogignore_digest: String::new(),
                    config_digest: String::new(),
                    decode_policy_version: 0,
                    source_policy_digest: String::new(),
                    guard_schema_version: 0,
                    report_semantics_version: 0,
                }),
                terminal_sequence: 0,
            };
            // Update the root record with the receipt. The root was
            // registered under the daemon-canonicalized path, so
            // canonicalize the transaction's repo_path to match.
            // Log errors so a failed update is visible to the operator.
            let commit_root = match std::fs::canonicalize(&txn.repo_path) {
                Ok(p) => p,
                Err(_) => std::path::PathBuf::from(&txn.repo_path),
            };
            if let Err(e) = state.guard.update_root_after_commit(std::os::unix::ffi::OsStrExt::as_bytes(commit_root.as_os_str()), receipt) {
                tracing::warn!(
                    "daemon: guard commit finish: failed to update root {}: {}",
                    commit_root.display(),
                    e
                );
            }
            Response::GuardCommitReceipt {
                objects_requested: total_objects,
                objects_hit,
                objects_scanned,
                objects_skipped: txn.objects_skipped,
                bytes_requested: txn.bytes_requested,
                bytes_hit,
                bytes_scanned: txn.bytes_scanned,
                findings_count: txn.findings_count,
                coverage_gaps: txn.coverage_gaps,
                terminal_state: terminal_state.label().to_string(),
                terminal_sequence: 0,
            }
        }
        Request::GuardAdd { root, mode } => {
            let guard_mode = match mode.as_str() {
                "repo" => keyhog_core::guard_state::GuardRootMode::Repo,
                "filesystem" => keyhog_core::guard_state::GuardRootMode::Filesystem,
                other => {
                    return Response::Error {
                        message: format!("daemon: invalid guard mode '{}': expected 'repo' or 'filesystem'", other),
                    }
                }
            };
            // Canonicalize the path server-side. The client sends
            // an absolute path, but the daemon must verify it does
            // not contain `..` segments or symlinked intermediates
            // that would resolve to an unexpected directory.
            let canonical_path = match std::fs::canonicalize(&root) {
                Ok(p) => p,
                Err(e) => {
                    return Response::Error {
                        message: format!("daemon: guard add: cannot canonicalize {}: {}", root, e),
                    };
                }
            };
            let canonical = canonical_path.to_string_lossy().into_owned();
            // Reject system directories that should never be guard
            // roots. The socket is same-uid only, but a same-user
            // process should not be able to make the daemon scan
            // sensitive system paths or consume watch descriptors
            // on OS internals.
            if is_system_path(&canonical_path) {
                return Response::Error {
                    message: format!(
                        "daemon: guard add: refusing to register system path {}: guard roots must be project or user directories",
                        canonical
                    ),
                };
            }
            // Use symlink_metadata to avoid following symlinks. The design
            // contract requires roots be validated without following symlinks.
            let meta = match std::fs::symlink_metadata(&canonical_path) {
                Ok(m) => m,
                Err(e) => {
                    return Response::Error {
                        message: format!("daemon: guard add: path does not exist: {}: {}", canonical, e),
                    };
                }
            };
            if !meta.is_dir() {
                return Response::Error {
                    message: format!("daemon: guard add: path is not a directory: {}", canonical),
                };
            }
            let fs_identity = filesystem_identity(&canonical_path);
            match state.guard.add_root(canonical.as_bytes().to_vec(), fs_identity, guard_mode) {
                Ok(record) => {
                    // Register the root with the filesystem watcher.
                    // Subscribe-first: the watcher starts before any
                    // baseline walk so events during the walk are
                    // captured. If the watcher cannot observe this
                    // root (e.g. inotify watch limit exceeded), fail
                    // the registration: the root is removed from the
                    // guard runtime so `guard status` does not report
                    // a protected root that is silently unwatched.
                    if let Err(e) = state.guard_watcher.lock().add_root(canonical_path.clone()) {
                        tracing::warn!(
                            "daemon: guard watcher failed to register {}: {}",
                            canonical,
                            e
                        );
                        let _ = state.guard.remove_root(canonical.as_bytes());
                        return Response::Error {
                            message: format!(
                                "daemon: guard add: watcher cannot observe {}: {}",
                                canonical,
                                e
                            ),
                        };
                    }
                    Response::GuardAdded {
                        root: canonical.clone(),
                        state: record.state.label().to_string(),
                        terminal_sequence: record.terminal_sequence,
                    }
                }
                Err(msg) => Response::Error { message: format!("daemon: guard add failed: {}", msg) },
            }
        }
        Request::GuardRemove { root } => {
            match state.guard.remove_root(root.as_bytes()) {
                Some(_) => {
                    state.guard_watcher.lock().remove_root(std::path::Path::new(&root));
                    Response::GuardRemoved
                }
                None => Response::Error {
                    message: format!("daemon: guard root not registered: {}", root),
                },
            }
        }
        Request::GuardStatus { root } => {
            match state.guard.root_record(root.as_bytes()) {
                Some(record) => {
                    let (files_scanned, bytes_scanned, attestation_hits, attestation_misses, findings_count, coverage_gaps) =
                        if let Some(ref receipt) = record.last_receipt {
                            (
                                receipt.objects_scanned,
                                receipt.bytes_scanned,
                                receipt.objects_hit,
                                receipt.objects_requested - receipt.objects_hit - receipt.objects_skipped,
                                receipt.findings_count,
                                receipt.coverage_gaps,
                            )
                        } else {
                            (0, 0, 0, 0, 0, 0)
                        };
                    Response::GuardStatusResult {
                        root: root.clone(),
                        mode: record.mode.label().to_string(),
                        state: record.state.label().to_string(),
                        terminal_sequence: record.terminal_sequence,
                        accepted_event_sequence: record.accepted_event_sequence,
                        completed_event_sequence: record.completed_event_sequence,
                        pending_events: state.guard_watcher.lock().pending_event_count(std::path::Path::new(&root)) as u64,
                        files_scanned,
                        bytes_scanned,
                        attestation_hits,
                        attestation_misses,
                        findings_count,
                        coverage_gaps,
                        initial_reconciliation_time: record.initial_reconciliation_time,
                        last_reconciliation_time: record.last_reconciliation_time,
                        scanner_residency: state.guard.scanner_residency().to_string(),
                        backend_route_label: record.backend_route_label.clone(),
                        build_identity_short: state.guard.policy_identity()
                            .as_ref()
                            .and_then(|id| id.short_digest().ok())
                            .unwrap_or_default(),
                        detector_digest_short: state.guard.policy_identity()
                            .as_ref()
                            .map(|id| id.detector_digest.get(..12).unwrap_or(&id.detector_digest).to_string())
                            .unwrap_or_default(),
                        suppression_digest_short: state.guard.policy_identity()
                            .as_ref()
                            .map(|id| id.suppression_digest.get(..12).unwrap_or(&id.suppression_digest).to_string())
                            .unwrap_or_default(),
                        config_digest_short: state.guard.policy_identity()
                            .as_ref()
                            .map(|id| id.config_digest.get(..12).unwrap_or(&id.config_digest).to_string())
                            .unwrap_or_default(),
                        autoroute_evidence_status: state.guard.autoroute_evidence_status().to_string(),
                        store_schema_version: keyhog_core::guard_state::GUARD_SCHEMA_VERSION,
                        store_path: String::new(),
                        repair_command: format!("keyhog guard reconcile {}", root),
                    }
                }
                None => Response::Error {
                    message: format!("daemon: guard root not registered: {}", root),
                },
            }
        }
        Request::GuardReconcile { root } => {
            let current_state = match state.guard.root_state(root.as_bytes()) {
                Some(s) => s,
                None => {
                    return Response::Error {
                        message: format!("daemon: guard root not registered: {}", root),
                    };
                }
            };
            // Choose the correct transition based on current state.
            // Stopped -> ReconciliationStarted -> Indexing.
            // Degraded/StalePolicy -> RepairStarted -> Indexing.
            // Current/Dirty/Blocked -> Stopped -> ReconciliationStarted.
            let transition = match current_state {
                keyhog_core::guard_state::GuardRootState::Stopped => {
                    keyhog_core::guard_state::GuardTransition::ReconciliationStarted
                }
                keyhog_core::guard_state::GuardRootState::Degraded
                | keyhog_core::guard_state::GuardRootState::StalePolicy => {
                    keyhog_core::guard_state::GuardTransition::RepairStarted
                }
                keyhog_core::guard_state::GuardRootState::Current
                | keyhog_core::guard_state::GuardRootState::Dirty
                | keyhog_core::guard_state::GuardRootState::Blocked => {
                    // Stop first, then start reconciliation. The stop
                    // transition is always legal from active states.
                    match state.guard.transition_root(root.as_bytes(), &keyhog_core::guard_state::GuardTransition::Stopped) {
                        Ok(_) => {}
                        Err(e) => {
                            return Response::Error {
                                message: format!("daemon: guard reconcile: stop failed: {}", e),
                            };
                        }
                    }
                    keyhog_core::guard_state::GuardTransition::ReconciliationStarted
                }
                keyhog_core::guard_state::GuardRootState::Indexing => {
                    // Already indexing; report started without a transition.
                    return Response::GuardReconcileStarted { root: root.clone() };
                }
            };
            match state.guard.transition_root(root.as_bytes(), &transition) {
                Ok(_) => {}
                Err(e) => {
                    return Response::Error {
                        message: format!("daemon: guard reconcile failed: {}", e),
                    };
                }
            }
            // Perform the baseline scan and apply the terminal
            // transition. This runs synchronously so the caller gets
            // the final state in the response.
            let scan_result = perform_baseline_reconciliation(state, &root).await;
            let terminal = match scan_result {
                BaselineResult::Clean => {
                    keyhog_core::guard_state::GuardTransition::ReconciliationClean
                }
                BaselineResult::Findings => {
                    keyhog_core::guard_state::GuardTransition::ReconciliationFindings
                }
                BaselineResult::Degraded => {
                    keyhog_core::guard_state::GuardTransition::ReconciliationDegraded
                }
            };
            match state.guard.transition_root(root.as_bytes(), &terminal) {
                Ok(_) => {
                    // If filesystem events were observed during the
                    // baseline scan, the tree changed mid-walk and
                    // the scan may not have seen the latest content.
                    // Transition to Dirty so the operator knows a
                    // re-scan is needed. EventAccepted is legal from
                    // Current and Blocked, the two states the
                    // baseline terminal transition produces when the
                    // scan itself succeeded.
                    if state.guard.take_dirty_during_indexing(root.as_bytes()) {
                        if let Err(e) = state.guard.transition_root(
                            root.as_bytes(),
                            &keyhog_core::guard_state::GuardTransition::EventAccepted,
                        ) {
                            tracing::warn!(
                                "daemon: guard reconcile: dirty-during-indexing transition failed for {}: {}",
                                root,
                                e
                            );
                        }
                    }
                    Response::GuardReconcileStarted { root: root.clone() }
                }
                Err(e) => Response::Error {
                    message: format!("daemon: guard reconcile terminal transition failed: {}", e),
                },
            }
        }
        Request::GuardList => {
            let roots: Vec<crate::daemon::protocol::GuardListEntry> = state
                .guard
                .list_roots()
                .into_iter()
                .map(|r| crate::daemon::protocol::GuardListEntry {
                    root: String::from_utf8_lossy(&r.canonical_path).into_owned(),
                    mode: r.mode.label().to_string(),
                    state: r.state.label().to_string(),
                    terminal_sequence: r.terminal_sequence,
                })
                .collect();
            Response::GuardListResult { roots }
        }
        // The wire contract says Shutdown flushes in-flight scans. Refuse new
        // work, wait for the running scans, and only then acknowledge, so a
        // client whose scan is mid-flight gets its results instead of a dropped
        // socket. Bounded: one wedged transaction must not make the daemon
        // unstoppable (KH-550).
        Request::Shutdown => {
            let stuck = state.drain_active_work(SHUTDOWN_DRAIN_TIMEOUT).await;
            if stuck > 0 {
                let palette = style::for_stderr();
                eprintln!(
                    "{} keyhog daemon: shutting down with {stuck} unfinished request slot(s) after \
                     {}s; their clients will see a closed connection.",
                    style::warn("WARN", &palette),
                    SHUTDOWN_DRAIN_TIMEOUT.as_secs()
                );
            }
            Response::Shutdown
        }
    }
}

async fn scan_text(
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

async fn scan_path(
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
            let (chunks, source_coverage_gaps) = daemon_scan_path_chunks(&resolved_owned)?;
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
            }
        }
        Ok(Err(error)) => MassBatchDispatch::error(format!("daemon: mass batch failed: {error:#}")),
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

/// An open, no-follow handle to the exact regular file one `ScanPath` request
/// named. Held for the whole scan so the inode cannot be recycled underneath the
/// read, and re-checked afterwards against the pathname.
struct PinnedFile(std::fs::File);

/// Open `path` without following a final symlink and require a regular file.
///
/// `ScanPath` is documented as a regular-file request and the client checks that
/// before sending, but the server is the side that must enforce it: without this
/// a directory argument makes the daemon walk and scan an entire tree while
/// holding the fragment lease, and a FIFO or socket argument turns a scan into an
/// open on a file type the source layer never promised to handle.
fn pin_regular_file(path: &Path) -> std::result::Result<PinnedFile, String> {
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

fn refused_file_type_message(path: &Path, file_type: &std::fs::FileType) -> String {
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

fn file_type_label(file_type: &std::fs::FileType) -> &'static str {
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

/// Get the filesystem identity (device + inode) for a path. Returns
/// zeros if the path cannot be stat'd, which is sufficient for
/// registration; the root existence check happens separately.
fn filesystem_identity(path: &std::path::Path) -> keyhog_core::guard_state::FilesystemIdentity {
    use std::os::unix::fs::MetadataExt;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => keyhog_core::guard_state::FilesystemIdentity {
            device: meta.dev(),
            inode: meta.ino(),
        },
        Err(_) => keyhog_core::guard_state::FilesystemIdentity {
            device: 0,
            inode: 0,
        },
    }
}

/// Compute the Git blob OID for a payload. Git stores blobs as
/// `blob <size>\0<content>` and hashes with SHA-1 or SHA-256.
fn compute_git_blob_oid(
    algorithm: keyhog_core::guard_state::GitHashAlgorithm,
    payload: &[u8],
) -> String {
    use keyhog_core::guard_state::GitHashAlgorithm;
    let header = format!("blob {}\0", payload.len());
    match algorithm {
        GitHashAlgorithm::Sha1 => {
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(header.as_bytes());
            hasher.update(payload);
            hex::encode(hasher.finalize())
        }
        GitHashAlgorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(header.as_bytes());
            hasher.update(payload);
            hex::encode(hasher.finalize())
        }
    }
}

/// Result of a baseline reconciliation scan.
enum BaselineResult {
    /// No findings, no coverage gaps.
    Clean,
    /// Unsuppressed findings detected.
    Findings,
    /// Coverage gaps or scan errors.
    Degraded,
}

/// Perform a baseline scan of a guard root. Walks the filesystem
/// source, scans every chunk, and returns the terminal result.
async fn perform_baseline_reconciliation(state: &ServerState, root: &str) -> BaselineResult {
    let scanner = state.scanner.clone();
    let router = state.router.clone();
    let backend_override = state.backend_override;
    let recover_automatic_backend_faults = crate::orchestrator::automatic_backend_recovery_allowed(
        backend_override,
        false,
        keyhog_scanner::gpu::gpu_runtime_policy(),
    );
    let fragment_scan_lock = state.fragment_scan_lock.clone();
    let root_path = std::path::PathBuf::from(root);
    let guard_filter = state.guard_filter.clone();
    let _fragment_guard = fragment_scan_lock.lock_owned().await;
    scanner.clear_fragment_cache();
    let skip_before = keyhog_sources::skip_counts();
    let result = tokio::task::spawn_blocking(move || -> Result<(usize, usize)> {
        let source = keyhog_sources::FilesystemSource::new(root_path.clone());
        let mut total_findings = 0usize;
        let mut total_gaps = 0usize;
        for chunk_result in source.chunks() {
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(_) => {
                    total_gaps += 1;
                    continue;
                }
            };
            if chunk.data.is_empty() {
                continue;
            }
            let telemetry = std::sync::Arc::new(keyhog_scanner::telemetry::ScanTelemetry::new());
            let scan_out = keyhog_scanner::telemetry::with_scan_telemetry(
                &telemetry,
                || -> Result<Vec<RawMatch>> {
                    let batch = vec![chunk];
                    let total_bytes: usize = batch.iter().map(|c| c.data.len()).sum();
                    keyhog_profile::add_input_units(1);
                    keyhog_profile::add_input_bytes(total_bytes as u64);
                    let selection = router.choose_with_plan(
                        scanner.as_ref(),
                        backend_override,
                        &batch,
                    )?;
                    let outcome = crate::orchestrator::scan_selected_batch(
                        scanner.as_ref(),
                        &batch,
                        selection.backend,
                        selection.phase1_plan.as_ref(),
                        selection.execution_route,
                        selection
                            .recovery_plan
                            .filter(|_| recover_automatic_backend_faults),
                    )
                    .with_context(|| {
                        format!(
                            "daemon: guard baseline scan failed for {}",
                            root_path.display()
                        )
                    })?;
                    let raw: Vec<RawMatch> =
                        outcome.per_chunk.into_iter().flatten().collect();
                    Ok(raw)
                },
            );
            match scan_out {
                Ok(raw_matches) => {
                    match guard_filter.finalize_count(&scanner, raw_matches) {
                        Some(count) => total_findings += count,
                        None => total_gaps += 1,
                    }
                }
                Err(_) => {
                    total_gaps += 1;
                }
            }
        }
        Ok((total_findings, total_gaps))
    })
    .await;
    // Count files the source quietly skipped (oversized, binary,
    // unreadable, truncated) as coverage gaps. The source records
    // these in process-global counters rather than as Err items.
    let skip_after = keyhog_sources::skip_counts();
    let skip_delta = skip_after.total().saturating_sub(skip_before.total());
    match result {
        Ok(Ok((findings, gaps))) => {
            let total_gaps = gaps + skip_delta;
            if total_gaps > 0 {
                BaselineResult::Degraded
            } else if findings > 0 {
                BaselineResult::Findings
            } else {
                BaselineResult::Clean
            }
        }
        _ => BaselineResult::Degraded,
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
// Sibling file (daemon/request_profile_tests.rs), not server/ subdir.
#[path = "request_profile_tests.rs"]
mod request_profile_tests;

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
            }
        });
        super::finish_daemon_service(&socket_path, accept_task).await
    }
}
