//! Daemon client: connect to a running `keyhog daemon` and exchange
//! one request/response pair at a time over a Unix socket.

use crate::daemon::frame;
use crate::daemon::protocol::{Request, Response, WIRE_VERSION};
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::time::Duration;
use tokio::io::{BufReader, BufWriter};
use tokio::net::UnixStream;

/// Open a connection to the daemon and send `Hello` first to confirm
/// a compatible wire version. Returns the live stream split into
/// reader and writer halves; subsequent request/response cycles
/// reuse them.
pub async fn connect(socket_path: &Path) -> Result<Client> {
    // 1 s connect ceiling so a stale socket file with no listener
    // fails fast instead of blocking the CLI for the kernel's
    // default connect timeout (which on Linux ranges into multiple
    // seconds).
    let stream = tokio::time::timeout(
        Duration::from_secs(1),
        UnixStream::connect(socket_path),
    )
    .await
    .with_context(|| format!("daemon client: connect timeout to {}", socket_path.display()))?
    .with_context(|| format!("daemon client: connect to {}", socket_path.display()))?;

    let (reader, writer) = stream.into_split();
    let mut client = Client {
        reader: BufReader::new(reader),
        writer: BufWriter::new(writer),
    };

    // Hello handshake gates the connection on wire compatibility. A
    // mismatched daemon could silently mis-deserialize fields and
    // return garbage; refuse the connection up front so the CLI can
    // either upgrade the daemon, fall back to in-process, or fail
    // cleanly.
    client.send(&Request::Hello).await?;
    match client.recv().await? {
        Response::Hello { wire_version, .. } if wire_version == WIRE_VERSION => Ok(client),
        Response::Hello {
            wire_version,
            keyhog_version,
            ..
        } => bail!(
            "daemon wire version mismatch: client expects {WIRE_VERSION}, daemon at {} reports {wire_version} (keyhog {keyhog_version}). Restart the daemon or pass --no-daemon.",
            socket_path.display(),
        ),
        other => bail!("daemon client: expected Hello reply, got {other:?}"),
    }
}

pub struct Client {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: BufWriter<tokio::net::unix::OwnedWriteHalf>,
}

impl Client {
    pub async fn send(&mut self, request: &Request) -> Result<()> {
        frame::write_request(&mut self.writer, request).await
    }

    pub async fn recv(&mut self) -> Result<Response> {
        match frame::read_response(&mut self.reader).await? {
            Some(r) => Ok(r),
            None => bail!("daemon client: connection closed before response"),
        }
    }

    pub async fn round_trip(&mut self, request: &Request) -> Result<Response> {
        self.send(request).await?;
        self.recv().await
    }
}
