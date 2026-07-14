//! Daemon client: connect to a running `keyhog daemon` and exchange
//! one request/response pair at a time over a Unix socket.

use crate::daemon::frame;
use crate::daemon::protocol::{response_kind, Request, Response, WIRE_VERSION};
use crate::daemon::trust;
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

/// Open a connection to the daemon and confirm wire, build, and detector-corpus
/// compatibility with this client. Use this
/// for the scan route: a daemon left running across a `keyhog update` would
/// otherwise keep serving scans with its OLD detector corpus, silently
/// returning stale results to the upgraded client. Returns the live stream
/// split into reader and writer halves.
pub async fn connect(socket_path: &Path) -> Result<Client> {
    connect_inner(socket_path, true).await
}

/// Connect WITHOUT the build/corpus staleness rejection. Wire compatibility
/// and canonical handshake fields remain enforced. `daemon stop` and
/// `daemon status` use this so an operator can still stop or inspect a daemon
/// left running across an upgrade
/// (the whole point of `stop` on a stale daemon is to clear it; refusing on a
/// version mismatch would strand it). The wire-version gate still applies
/// because a wire-incompatible daemon cannot be framed at all.
pub async fn connect_any_version(socket_path: &Path) -> Result<Client> {
    connect_inner(socket_path, false).await
}

async fn connect_inner(socket_path: &Path, require_same_version: bool) -> Result<Client> {
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
            let expected_rules_digest = embedded_detector_rules_digest()?;
            let mut mismatches = Vec::new();
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
            if detector_rules_digest != expected_rules_digest {
                mismatches.push(format!(
                    "detector rules daemon={detector_rules_digest}, client={expected_rules_digest}"
                ));
            }
            let stale_reason = (!mismatches.is_empty()).then(|| mismatches.join("; "));
            if require_same_version && stale_reason.is_some() {
                bail!(
                    "daemon identity mismatch at {}: {}. It may hold a different build, \
                     detector corpus, or scan pipeline and would return stale scan results. Restart it with \
                     `keyhog daemon stop && keyhog daemon start`, or pass `--daemon=off` to \
                     scan in-process.",
                    socket_path.display(),
                    stale_reason.as_deref().unwrap_or("unknown identity mismatch"), // LAW10: reporting-only fallback inside an already fail-closed identity-mismatch error
                );
            }
            // Record the daemon's reported version so callers that tolerate a
            // mismatch (`status`) can still surface staleness to the operator.
            client.daemon_version = keyhog_version;
            client.backend_policy = backend_policy;
            client.stale_reason = stale_reason;
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

pub struct Client {
    transport: frame::ClientTransport,
    /// The `keyhog_version` the daemon reported in its `Hello`. Set during
    /// `connect`/`connect_any_version`. Lets `daemon status` warn loudly when a
    /// daemon left running across an upgrade is now stale.
    daemon_version: String,
    /// Canonical daemon-owned route policy received in the Hello handshake.
    backend_policy: String,
    stale_reason: Option<String>,
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

    /// `true` when the daemon package, Git build, or detector rules differ from
    /// this client. `connect` refuses such a daemon; `connect_any_version`
    /// tolerates it so status/stop can diagnose and clear stale state.
    pub(crate) fn is_stale(&self) -> bool {
        self.stale_reason.is_some()
    }

    pub(crate) fn stale_reason(&self) -> Option<&str> {
        self.stale_reason.as_deref()
    }

    pub(crate) async fn send(&mut self, request: &Request) -> Result<()> {
        self.transport.send(request.clone()).await
    }

    pub(crate) async fn recv(&mut self) -> Result<Response> {
        match self.transport.next().await.transpose()? {
            Some(r) => Ok(r),
            None => bail!(
                "daemon client: connection closed before response. \
                 The daemon may have crashed or been restarted mid-request. \
                 Try `keyhog daemon stop && keyhog daemon start`, or rerun \
                 the scan with `--daemon=off` to bypass the daemon path."
            ),
        }
    }

    pub(crate) async fn round_trip(&mut self, request: &Request) -> Result<Response> {
        self.send(request).await?;
        self.recv().await
    }
}

fn validate_backend_policy(policy: &str) -> Result<()> {
    if policy == "autoroute" {
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
    let detectors = keyhog_core::load_embedded_detectors_or_fail()
        .context("daemon client: load embedded detector identity")?;
    Ok(keyhog_core::hex_encode(&keyhog_core::compute_spec_hash(
        &detectors,
    )))
}
