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
/// in its `Hello` is running an older (or newer) binary — and therefore a
/// possibly-different detector corpus + scan pipeline — than the client that
/// just upgraded. Routing scans to it would silently return stale-corpus
/// results, so [`connect`] fails closed on a mismatch.
const CLIENT_KEYHOG_VERSION: &str = env!("CARGO_PKG_VERSION");
const DAEMON_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

/// Open a connection to the daemon and confirm BOTH wire compatibility AND
/// that the daemon is running the SAME keyhog version as this client. Use this
/// for the scan route: a daemon left running across a `keyhog update` would
/// otherwise keep serving scans with its OLD detector corpus, silently
/// returning stale results to the upgraded client. Returns the live stream
/// split into reader and writer halves.
pub async fn connect(socket_path: &Path) -> Result<Client> {
    connect_inner(socket_path, true).await
}

/// Connect WITHOUT the keyhog-version staleness check — only wire
/// compatibility is enforced. `daemon stop` / `daemon status` use this so an
/// operator can still stop or inspect a daemon left running across an upgrade
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
            ..
        } if wire_version == WIRE_VERSION => {
            // Staleness gate: the wire version can stay stable across keyhog
            // releases that change the DETECTOR CORPUS or scan pipeline (e.g.
            // 0.5.40 -> 0.5.41, both wire v2). A daemon started before a
            // `keyhog update` keeps the old scanner in memory and would serve
            // the upgraded client OLD-corpus results — a silent recall/precision
            // divergence the wire check cannot catch. Refuse so the scan path
            // never depends on whether a stale daemon happens to be running.
            if require_same_version && keyhog_version != CLIENT_KEYHOG_VERSION {
                bail!(
                    "daemon version mismatch: this keyhog is {CLIENT_KEYHOG_VERSION} but the \
                     daemon at {} is running {keyhog_version}: it holds an OLDER detector \
                     corpus in memory and would return stale scan results. Restart it with \
                     `keyhog daemon stop && keyhog daemon start`, or pass `--daemon=off` to \
                     scan in-process.",
                    socket_path.display(),
                );
            }
            // Record the daemon's reported version so callers that tolerate a
            // mismatch (`status`) can still surface staleness to the operator.
            client.daemon_version = keyhog_version;
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
}

impl Client {
    /// The keyhog version the connected daemon reported. Empty only if the
    /// handshake did not complete (it always does on a returned `Client`).
    pub(crate) fn daemon_version(&self) -> &str {
        &self.daemon_version
    }

    /// `true` when the daemon is running a DIFFERENT keyhog version than this
    /// client — i.e. a daemon left running across a `keyhog update`, now
    /// serving an older detector corpus. `connect` refuses such a daemon;
    /// `connect_any_version` tolerates it, so its callers use this to warn.
    pub(crate) fn is_stale(&self) -> bool {
        !self.daemon_version.is_empty() && self.daemon_version != CLIENT_KEYHOG_VERSION
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
