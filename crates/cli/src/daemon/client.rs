//! Daemon client: connect to a running `keyhog daemon`, exchange ordinary
//! request/response pairs, and receive the bounded mass-filesystem response stream.

use crate::daemon::frame;
use crate::daemon::protocol::{response_kind, Request, Response, WarmBackendStatus, WIRE_VERSION};
use crate::daemon::sigpipe;
use crate::daemon::trust;
use crate::daemon::warm_identity;
use anyhow::{bail, Context, Result};
use futures_util::{SinkExt, StreamExt};
use std::path::Path;
use std::time::Duration;
use tokio::net::UnixStream;

/// This client binary's keyhog version. A daemon reporting a DIFFERENT version
/// in its `Hello` is running an older (or newer) binary, and therefore a
/// possibly-different detector corpus + scan pipeline, than the client that
/// just upgraded. Routing scans to it would silently return stale-corpus
/// results, so [`connect`] fails closed on a mismatch.
const CLIENT_KEYHOG_VERSION: &str = env!("CARGO_PKG_VERSION");
const DAEMON_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
/// Default ceiling for ScanPath (KH-1314). A wedged daemon must not hang the
/// CLI forever. Per-kind ceilings in [`request_timeout`] (KH-1459).
const DAEMON_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);
const DAEMON_HEALTH_TIMEOUT: Duration = Duration::from_secs(5);
/// `Shutdown` is answered only after the daemon has flushed in-flight work to
/// its clients, which the server bounds by its own drain deadline. This ceiling
/// sits above that bound so `daemon stop` observes the completed drain instead of
/// reporting a timeout against a daemon that is stopping correctly.
const DAEMON_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);
const DAEMON_SCAN_TEXT_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-request-kind receive timeout (KH-1459). Health stays short so a stuck
/// daemon does not block operator control; Shutdown allows for the server-side
/// drain; ScanPath keeps the 300s full-file budget; ScanText is mid-tier for
/// pre-commit chunks.
fn request_timeout(request: &Request) -> Duration {
    match request {
        Request::Hello
        | Request::Health
        | Request::MassBegin { .. }
        | Request::MassFilesystemBegin { .. }
        | Request::MassEnd
        | Request::GuardAdd { .. }
        | Request::GuardRemove { .. }
        | Request::GuardStatus { .. }
        | Request::GuardList => DAEMON_HEALTH_TIMEOUT,
        Request::Shutdown => DAEMON_SHUTDOWN_TIMEOUT,
        Request::ScanText { .. } => DAEMON_SCAN_TEXT_TIMEOUT,
        Request::ScanPath { .. }
        | Request::MassBatch { .. }
        | Request::MassFilesystemDrain
        | Request::GuardCommitBegin { .. }
        | Request::GuardCommitBlob { .. }
        | Request::GuardCommitFinish { .. }
        | Request::GuardReconcile { .. } => DAEMON_REQUEST_TIMEOUT,
    }
}

/// Open a connection to the daemon and confirm wire, build, and detector-corpus
/// compatibility with this client. Use this
/// for the scan route: a daemon left running across a `keyhog update` would
/// otherwise keep serving scans with its OLD detector corpus, silently
/// returning stale results to the upgraded client. Returns the live stream
/// split into reader and writer halves.
pub(crate) async fn connect(socket_path: &Path) -> Result<Client> {
    connect_inner(socket_path, true, None).await
}
/// Open a scan connection while validating against the detector corpus the
/// client actually selected. The expected digest is client-derived; the
/// daemon's Hello value is never used as its own expectation.
pub(crate) async fn connect_with_detector_rules_digest(
    socket_path: &Path,
    expected_detector_rules_digest: String,
) -> Result<Client> {
    connect_inner(socket_path, true, Some(expected_detector_rules_digest)).await
}

/// Connect WITHOUT the build/corpus staleness rejection. Wire compatibility
/// and canonical handshake fields remain enforced. `daemon stop` and
/// `daemon status` use this so an operator can still stop or inspect a daemon
/// left running across an upgrade
/// (the whole point of `stop` on a stale daemon is to clear it; refusing on a
/// version mismatch would strand it). The wire-version gate still applies
/// because a wire-incompatible daemon cannot be framed at all.
pub(crate) async fn connect_any_version(socket_path: &Path) -> Result<Client> {
    connect_inner(socket_path, false, None).await
}

#[cfg(test)]
/// Return the exact client-owned portion of the warm-route identity.
pub(crate) fn current_warm_backend_identity(
    detector_rules_digest: String,
) -> Result<crate::daemon::protocol::WarmBackendIdentity> {
    warm_identity::client_identity(detector_rules_digest)
}

pub(crate) fn current_warm_backend_mismatches(status: &WarmBackendStatus) -> Result<Vec<String>> {
    let detector_rules_digest = embedded_detector_rules_digest()?;
    let expected = warm_identity::client_identity(detector_rules_digest)?;
    Ok(warm_identity::validate_for_client(status, &expected))
}

async fn connect_inner(
    socket_path: &Path,
    require_same_version: bool,
    expected_detector_rules_digest: Option<String>,
) -> Result<Client> {
    trust::validate_socket_for_connect(socket_path)?;
    // 1 s connect ceiling so a stale socket file with no listener
    // fails fast instead of blocking the CLI for the kernel's
    // default connect timeout (which on Linux ranges into multiple
    // seconds).
    let stream = tokio::time::timeout(Duration::from_secs(1), UnixStream::connect(socket_path))
        .await
        .with_context(|| {
            format!(
                "daemon client: connect timeout to {}",
                socket_path.display()
            )
        })?
        .with_context(|| format!("daemon client: connect to {}", socket_path.display()))?;
    trust::verify_connected_peer(&stream, socket_path)?;

    let mut client = Client {
        transport: frame::client_transport(stream),
        daemon_version: String::new(),
        backend_policy: String::new(),
        stale_reason: None,
        warm_backend: None,
        mass_service: false,
        mass_gpu_primary_required: false,
        _sigpipe: sigpipe::SigPipeGuard::acquire(),
    };

    // Hello handshake gates the connection on wire compatibility. A
    // mismatched daemon could silently mis-deserialize fields and
    // return garbage; refuse the connection up front so the CLI can
    // either upgrade the daemon, fall back to in-process, or fail
    // cleanly.
    client.send(&Request::Hello).await?;
    let response = tokio::time::timeout(DAEMON_HANDSHAKE_TIMEOUT, client.recv())
        .await
        .with_context(|| {
            format!(
                "daemon client: handshake timeout waiting for Hello from {}",
                socket_path.display()
            )
        })?
        .with_context(|| {
            format!(
                "daemon client: handshake receive from {}",
                socket_path.display()
            )
        })?;
    match response {
        Response::Hello {
            wire_version,
            keyhog_version,
            git_hash,
            detector_rules_digest,
            backend_policy,
            warm_backend,
            mass_service,
            mass_gpu_primary_required,
            ..
        } if wire_version == WIRE_VERSION => {
            validate_backend_policy(&backend_policy)?;
            // Staleness gate: the wire version can stay stable across keyhog
            // releases that change the DETECTOR CORPUS or scan pipeline (e.g.
            // 0.5.40 -> 0.5.41). A daemon started before a
            // `keyhog update` keeps the old scanner in memory and would serve
            // the upgraded client OLD-corpus results, a silent recall/precision
            // divergence the wire check cannot catch. Refuse so the scan path
            // never depends on whether a stale daemon happens to be running.
            let expected_rules_digest = match expected_detector_rules_digest {
                Some(digest) => digest,
                None => embedded_detector_rules_digest()?,
            };
            let expected_warm_identity = if require_same_version {
                warm_identity::client_identity(expected_rules_digest.clone())?
            } else {
                warm_identity::client_control_identity(
                    expected_rules_digest.clone(),
                    &warm_backend.identity.binary_sha256,
                )
            };
            let mut mismatches =
                warm_identity::validate_for_client(&warm_backend, &expected_warm_identity);
            if keyhog_version != CLIENT_KEYHOG_VERSION {
                mismatches.push(format!(
                    "package version daemon={keyhog_version}, client={CLIENT_KEYHOG_VERSION}"
                ));
            }
            if git_hash != keyhog_core::git_hash() {
                mismatches.push(format!(
                    "Git build daemon={git_hash}, client={}",
                    keyhog_core::git_hash()
                ));
            }
            if detector_rules_digest != warm_backend.identity.detector_rules_digest {
                mismatches.push(format!(
                    "daemon Hello identity is inconsistent: detector_rules_digest={detector_rules_digest}, warm_backend.detector_rules_digest={}",
                    warm_backend.identity.detector_rules_digest
                ));
            }
            let stale_reason = (!mismatches.is_empty()).then(|| mismatches.join("; "));
            if require_same_version {
                if let Some(reason) = stale_reason.as_deref() {
                    bail!(
                        "daemon identity mismatch at {}: {}. It may hold a different build, \
                         detector corpus, scan pipeline, accelerator artifact, or resolved config and \
                         would return stale scan results. Restart it with \
                         `keyhog daemon stop && keyhog daemon start`, or pass `--daemon=off` to \
                         scan in-process.",
                        socket_path.display(),
                        reason,
                    );
                }
            }
            // Record the daemon's reported version so callers that tolerate a
            // mismatch (`status`) can still surface staleness to the operator.
            client.daemon_version = keyhog_version;
            client.backend_policy = backend_policy;
            client.stale_reason = stale_reason;
            client.warm_backend = Some(warm_backend);
            client.mass_service = mass_service;
            client.mass_gpu_primary_required = mass_gpu_primary_required;
            Ok(client)
        }
        Response::Hello {
            wire_version,
            keyhog_version,
            ..
        } => bail!(
            "daemon wire version mismatch: client expects {WIRE_VERSION}, daemon at {} reports {wire_version} (keyhog {keyhog_version}). Restart the daemon or pass --daemon=off.",
            socket_path.display(),
        ),
        other => bail!(
            "daemon client: expected Hello reply, got {}. Restart the daemon or pass --daemon=off.",
            response_kind(&other)
        ),
    }
}

#[doc(hidden)]
pub(crate) mod testing {
    pub(crate) use crate::daemon::trust::testing::{
        connected_peer_uid, current_uid, validate_socket_for_connect,
    };
}

#[path = "client_tests.rs"]
mod client_tests;

pub(crate) struct Client {
    transport: frame::ClientTransport,
    /// The `keyhog_version` the daemon reported in its `Hello`. Set during
    /// `connect`/`connect_any_version`. Lets `daemon status` warn loudly when a
    /// daemon left running across an upgrade is now stale.
    daemon_version: String,
    /// Canonical daemon-owned route policy received in the Hello handshake.
    backend_policy: String,
    stale_reason: Option<String>,
    warm_backend: Option<WarmBackendStatus>,
    mass_service: bool,
    mass_gpu_primary_required: bool,
    /// Alive for the whole connection so a daemon that dies or closes mid-write
    /// surfaces `EPIPE` on the socket instead of killing this process with
    /// `SIGPIPE`. Dropped with the connection, before report writing, so the
    /// piped-stdout contract `main::reset_sigpipe` exists for is unchanged.
    _sigpipe: sigpipe::SigPipeGuard,
}

impl Client {
    /// The keyhog version the connected daemon reported. Empty only if the
    /// handshake did not complete (it always does on a returned `Client`).
    pub(crate) fn daemon_version(&self) -> &str {
        &self.daemon_version
    }

    /// `autoroute` or the canonical backend label forced at daemon startup.
    pub(crate) fn backend_policy(&self) -> &str {
        &self.backend_policy
    }

    /// `true` when warm initialization is incomplete or any package, engine,
    /// executable, Git build, detector, or resolved-config identity differs.
    /// `connect` refuses such a daemon; `connect_any_version` tolerates it so
    /// status/stop can diagnose and clear stale state.
    pub(crate) fn is_stale(&self) -> bool {
        self.stale_reason.is_some()
    }

    pub(crate) fn stale_reason(&self) -> Option<&str> {
        self.stale_reason.as_deref()
    }

    pub(crate) fn warm_backend_status(&self) -> Option<&WarmBackendStatus> {
        self.warm_backend.as_ref()
    }

    pub(crate) fn is_mass_service(&self) -> bool {
        self.mass_service
    }

    pub(crate) fn mass_gpu_primary_required(&self) -> bool {
        self.mass_gpu_primary_required
    }

    pub(crate) async fn send(&mut self, request: &Request) -> Result<()> {
        self.transport.send(request.clone()).await
    }

    pub(crate) async fn recv(&mut self) -> Result<Response> {
        self.recv_with_timeout(DAEMON_REQUEST_TIMEOUT).await
    }

    pub(crate) async fn recv_with_timeout(&mut self, timeout: Duration) -> Result<Response> {
        match tokio::time::timeout(timeout, self.transport.next()).await {
            // LAW10: fail-closed; timeout returns an operator-facing hard error with a repair command and selects no alternate route.
            Err(_) => bail!(
                "daemon client: no response within {}s. The daemon may be stuck \
                 or overloaded. Try `keyhog daemon stop && keyhog daemon start`, \
                 or rerun with `--daemon=off`.",
                timeout.as_secs()
            ),
            Ok(None) => bail!(
                "daemon client: connection closed before response. \
                 The daemon may have crashed or been restarted mid-request. \
                 Try `keyhog daemon stop && keyhog daemon start`, or rerun \
                 the scan with `--daemon=off` to bypass the daemon path."
            ),
            Ok(Some(frame)) => frame.context("daemon client: response frame error"),
        }
    }

    pub(crate) async fn round_trip(&mut self, request: &Request) -> Result<Response> {
        self.send(request).await?;
        self.recv_with_timeout(request_timeout(request)).await
    }
}

fn validate_backend_policy(policy: &str) -> Result<()> {
    if matches!(policy, "autoroute" | "autoroute-degraded") {
        return Ok(());
    }
    if keyhog_scanner::hw_probe::parse_backend_str(policy)
        .is_some_and(|backend| backend.label() == policy)
    {
        return Ok(());
    }
    bail!("daemon reported invalid backend policy {policy:?}. Restart it with this KeyHog build")
}

fn embedded_detector_rules_digest() -> Result<String> {
    Ok(keyhog_core::detector_digest().to_owned())
}
