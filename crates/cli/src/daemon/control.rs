//! Version-independent daemon administration channel.
//!
//! [`client`](super::client) is the scan channel: it deserializes the strongly
//! typed [`Response`](super::protocol::Response) and refuses any daemon whose
//! wire version, build, corpus, or resolved config differs, because routing a
//! scan to such a daemon would silently return results from a different
//! pipeline. That gate is correct for scans and wrong for administration: an
//! operator whose daemon predates the current `WIRE_VERSION` still has to be
//! able to see it and stop it. Refusing to talk to it strands a live process
//! holding the socket, and reporting it as absent is worse still.
//!
//! This channel therefore speaks only the parts of the wire that have never
//! changed: `<u32 BE length><JSON body>` framing, the `{"op": ...}` request
//! envelope, and the `{"kind": ...}` response envelope. Bodies are read as
//! `serde_json::Value`, so unknown or missing fields cannot make a live daemon
//! unreachable. It never carries scan traffic - only `hello`, `health`, and
//! `shutdown` - so nothing here can turn a version mismatch into findings from
//! the wrong pipeline.

use crate::daemon::sigpipe;
use crate::daemon::trust;
use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
/// Administration replies are a handful of small fields. Capping them far below
/// the scan wire's 64 MiB `MAX_FRAME_BYTES` means an announced length can never
/// make this client allocate a large buffer for a daemon that then stalls.
const CONTROL_MAX_FRAME_BYTES: u32 = 256 * 1024;
/// `Shutdown` is answered only after the daemon flushes in-flight work, so it
/// gets a ceiling above the server's drain bound rather than the short
/// diagnostic budget every other administration request uses.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(45);

/// Why a control connection could not be completed. `stop` and `status` must
/// tell these apart: absence means nothing is running, every other kind means
/// something IS running and must not be reported as stopped (KH-641).
#[derive(Debug)]
pub(crate) enum ControlError {
    /// No socket file, or a socket file with no listener behind it.
    Absent(anyhow::Error),
    /// A live socket that failed KeyHog's ownership and permission checks. The
    /// peer is deliberately left untouched.
    Untrusted(anyhow::Error),
    /// A live daemon that answered in a shape this build cannot read at all,
    /// or stopped answering mid-exchange.
    Unintelligible(anyhow::Error),
}

impl ControlError {
    /// One-word class for operator-facing messages.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Absent(_) => "absent",
            Self::Untrusted(_) => "untrusted",
            Self::Unintelligible(_) => "unintelligible",
        }
    }

    pub(crate) fn is_absent(&self) -> bool {
        matches!(self, Self::Absent(_))
    }

    pub(crate) fn into_error(self) -> anyhow::Error {
        match self {
            Self::Absent(error) | Self::Untrusted(error) | Self::Unintelligible(error) => error,
        }
    }
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent(error) | Self::Untrusted(error) | Self::Unintelligible(error) => {
                write!(f, "{error:#}")
            }
        }
    }
}

/// The subset of a daemon `Hello` that every wire version has carried. Both
/// fields are optional so a daemon that renames or drops one stays controllable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DaemonIdentity {
    pub wire_version: Option<u64>,
    pub keyhog_version: Option<String>,
}

impl std::fmt::Display for DaemonIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.wire_version, self.keyhog_version.as_deref()) {
            (Some(wire), Some(version)) => write!(f, "wire {wire}, keyhog {version}"),
            (Some(wire), None) => write!(f, "wire {wire}, keyhog version undeclared"),
            (None, Some(version)) => write!(f, "wire version undeclared, keyhog {version}"),
            (None, None) => write!(f, "no declared wire or package version"),
        }
    }
}

pub(crate) struct ControlChannel {
    stream: UnixStream,
    /// Alive for the whole administration exchange: a daemon that exits while
    /// this client is writing must surface `EPIPE`, not kill the CLI.
    _sigpipe: sigpipe::SigPipeGuard,
}

impl ControlChannel {
    /// Open a control connection and complete the version-independent handshake.
    /// The daemon requires `Hello` first on every connection, so the identity
    /// read here is also what makes later `health`/`shutdown` requests legal.
    pub(crate) async fn connect(
        socket_path: &Path,
    ) -> std::result::Result<(Self, DaemonIdentity), ControlError> {
        trust::validate_socket_for_connect(socket_path).map_err(|error| {
            // A missing socket file is absence; a present but unsafe one is not.
            if socket_path.exists() {
                ControlError::Untrusted(error)
            } else {
                ControlError::Absent(error)
            }
        })?;
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(socket_path))
            .await
            .map_err(|_| {
                ControlError::Unintelligible(anyhow!(
                    "daemon control: connect to {} timed out after {}s",
                    socket_path.display(),
                    CONNECT_TIMEOUT.as_secs()
                ))
            })?
            .map_err(|error| {
                let context = anyhow::Error::new(error).context(format!(
                    "daemon control: connect to {}",
                    socket_path.display()
                ));
                // ENOENT and ECONNREFUSED both mean nothing is serving here.
                ControlError::Absent(context)
            })?;
        trust::verify_connected_peer(&stream, socket_path).map_err(ControlError::Untrusted)?;

        let mut channel = Self {
            stream,
            _sigpipe: sigpipe::SigPipeGuard::acquire(),
        };
        let hello = channel.round_trip("hello", CONTROL_TIMEOUT).await?;
        let kind = hello.get("kind").and_then(serde_json::Value::as_str);
        if kind != Some("hello") {
            return Err(ControlError::Unintelligible(anyhow!(
                "daemon control: expected a hello reply from {}, got kind {}",
                socket_path.display(),
                kind.unwrap_or("<absent>") // LAW10: absent reply kind is optional diagnostic metadata; the control operation still returns its explicit protocol error.
            )));
        }
        let identity = DaemonIdentity {
            wire_version: hello
                .get("wire_version")
                .and_then(serde_json::Value::as_u64),
            keyhog_version: hello
                .get("keyhog_version")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
        };
        Ok((channel, identity))
    }

    /// Ask the daemon to shut down. Accepts any reply whose `kind` is
    /// `shutdown`, which is the one response shape every wire version emits for
    /// this request.
    pub(crate) async fn shutdown(&mut self) -> std::result::Result<(), ControlError> {
        // The daemon answers only after flushing in-flight work, so this waits
        // out its drain rather than reporting a timeout against a daemon that is
        // stopping correctly.
        let response = self.round_trip("shutdown", SHUTDOWN_TIMEOUT).await?;
        match response.get("kind").and_then(serde_json::Value::as_str) {
            Some("shutdown") => Ok(()),
            other => Err(ControlError::Unintelligible(anyhow!(
                "daemon control: shutdown was not acknowledged (reply kind {})",
                other.unwrap_or("<absent>") // LAW10: absent reply kind is optional diagnostic metadata; shutdown still returns an explicit unacknowledged error.
            ))),
        }
    }

    async fn round_trip(
        &mut self,
        op: &str,
        timeout: Duration,
    ) -> std::result::Result<serde_json::Value, ControlError> {
        let request = serde_json::json!({ "op": op });
        tokio::time::timeout(timeout, async {
            write_frame(&mut self.stream, &request).await?;
            read_frame(&mut self.stream).await
        })
        .await
        .map_err(|_| {
            ControlError::Unintelligible(anyhow!(
                "daemon control: {op} did not complete within {}s",
                timeout.as_secs()
            ))
        })?
        .map_err(ControlError::Unintelligible)
    }
}

async fn write_frame(stream: &mut UnixStream, value: &serde_json::Value) -> Result<()> {
    let body = serde_json::to_vec(value).context("daemon control: encode request")?;
    let length = u32::try_from(body.len())
        .map_err(|_| anyhow!("daemon control: request body exceeds the frame length prefix"))?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .context("daemon control: write frame length")?;
    stream
        .write_all(&body)
        .await
        .context("daemon control: write frame body")?;
    stream
        .flush()
        .await
        .context("daemon control: flush frame")?;
    Ok(())
}

async fn read_frame(stream: &mut UnixStream) -> Result<serde_json::Value> {
    let mut length = [0u8; 4];
    stream
        .read_exact(&mut length)
        .await
        .context("daemon control: read frame length")?;
    let length = u32::from_be_bytes(length);
    if length > CONTROL_MAX_FRAME_BYTES {
        anyhow::bail!(
            "daemon control: peer announced a {length} byte administration frame, above the \
             {CONTROL_MAX_FRAME_BYTES} byte ceiling"
        );
    }
    let mut body = vec![0u8; length as usize];
    stream
        .read_exact(&mut body)
        .await
        .context("daemon control: read frame body")?;
    serde_json::from_slice(&body).context("daemon control: parse reply")
}
