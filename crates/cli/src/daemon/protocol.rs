//! Wire protocol for the keyhog daemon.
//!
//! Both ends frame messages as `<u32 BE length><JSON body>`.
//! Length-prefix framing keeps the parse one allocation per message
//! and means a malformed client can't desync the server — the next
//! read either lands on the next length header or the connection
//! dies. JSON body is `serde_json` because it's already in the
//! dependency graph (the CLI's `--format json` reporter uses it) and
//! the protocol is low-throughput per scan, dominated by the
//! findings payload that has to be JSON-shaped anyway.

use keyhog_core::RawMatch;
use serde::{Deserialize, Serialize};

/// Bump on any incompatible wire-format change. Server replies with
/// its supported version in the [`Hello`] handshake; the client
/// refuses to talk to a daemon whose version doesn't match.
pub const WIRE_VERSION: u32 = 1;

/// Maximum length of a single framed message body. 64 MiB ceiling
/// matches `MAX_SCAN_CHUNK_BYTES * 64` so a chunk batch fits, but
/// bounds the recv buffer so a hostile client can't OOM the daemon
/// by lying about the length prefix.
pub const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// First message on every connection. Server replies with
    /// [`Response::Hello`] containing its `WIRE_VERSION` so the client
    /// can refuse mismatched daemons.
    Hello,
    /// Scan a single chunk of in-memory text. Returns matches
    /// directly. Use this for the pre-commit / stdin / HAR-line case
    /// where the client already has the bytes in hand.
    ScanText { path: Option<String>, text: String },
    /// Scan a filesystem path (a regular file) using the daemon's
    /// pre-compiled scanner. Path resolution happens on the daemon
    /// side; relative paths resolve against `working_dir`.
    ScanPath {
        path: String,
        working_dir: Option<String>,
    },
    /// Liveness + cheap status (uptime, scans served, detector count).
    Health,
    /// Graceful shutdown — daemon flushes in-flight scans, drops the
    /// socket, exits. The client side is `keyhog daemon stop`.
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Hello {
        wire_version: u32,
        keyhog_version: String,
        detector_count: usize,
        uptime_secs: u64,
    },
    /// Returned for `ScanText` and `ScanPath`. `matches` are the
    /// scanner's `RawMatch` outputs — same wire shape as
    /// `keyhog scan --format json`, so client code can hand them to
    /// the existing reporter without translation.
    ScanResults {
        path: Option<String>,
        matches: Vec<RawMatch>,
    },
    Health {
        uptime_secs: u64,
        scans_served: u64,
        active_scans: u32,
        detector_count: usize,
    },
    /// Anything that went wrong on the server side. Connection stays
    /// open so the client can retry with a different request.
    Error { message: String },
    /// Acknowledgement for `Shutdown`. The daemon closes the socket
    /// after sending this; the client should not write again.
    Shutdown,
}
