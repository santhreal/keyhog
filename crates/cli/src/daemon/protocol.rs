//! Wire protocol for the keyhog daemon.
//!
//! Both ends frame messages as `<u32 BE length><JSON body>`.
//! Length-prefix framing keeps the parse one allocation per message
//! and means a malformed client can't desync the server - the next
//! read either lands on the next length header or the connection
//! dies. JSON body is `serde_json` because it's already in the
//! dependency graph (the CLI's `--format json` reporter uses it) and
//! the protocol is low-throughput per scan, dominated by the
//! findings payload that has to be JSON-shaped anyway.

use keyhog_core::RawMatch;
use keyhog_scanner::telemetry::DogfoodEvent;
use serde::{Deserialize, Serialize};

/// Bump on any incompatible wire-format change. Server replies with
/// its supported version in the [`Hello`] handshake; the client
/// refuses to talk to a daemon whose version doesn't match.
///
/// History:
///
/// * v1 - initial daemon protocol. `ScanResults { matches }` only.
/// * v2 - `ScanResults` carries `engine_example_suppressions` and
///   `dogfood_events` so `--dogfood` and the suppressed-example
///   reporter summary work in daemon mode (without the bump the
///   client's telemetry counter stayed at 0 because telemetry lives
///   in process-local OnceLock cells and the daemon scanner never
///   propagated its own counts back).
pub const WIRE_VERSION: u32 = 2;

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
    /// Graceful shutdown - daemon flushes in-flight scans, drops the
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
    /// scanner's `RawMatch` outputs - same wire shape as
    /// `keyhog scan --format json`, so client code can hand them to
    /// the existing reporter without translation.
    ///
    /// `engine_example_suppressions` is the count of credentials the
    /// scanner pipeline matched and then suppressed as known examples
    /// (`*EXAMPLE`, `DUMMY`, etc.) inside the daemon's process. The
    /// client merges this into its own telemetry counter so the
    /// empty-findings reporter line ("0 real secrets, but N
    /// example/test keys suppressed") fires even when the suppression
    /// happened on the other side of the socket.
    ///
    /// `dogfood_events` is non-empty only when the daemon was started
    /// with `KEYHOG_DOGFOOD=1` in its environment, OR when a
    /// future protocol lets the client toggle dogfood per-request.
    /// Today we ship the env-var path because it requires zero
    /// per-request wire change and `keyhog scan --dogfood` users who
    /// also need daemon mode can `KEYHOG_DOGFOOD=1 keyhog daemon
    /// start`.
    ScanResults {
        path: Option<String>,
        /// Security: each `RawMatch` carries the *unredacted* plaintext
        /// credential (`RawMatch::credential`), so this field puts every
        /// discovered secret on the wire in the clear. The sole control
        /// is the daemon socket's `0600` mode (same-uid trust model): the
        /// server hard-fails startup if that chmod does not stick (see
        /// `server::set_socket_mode_user_only`), so nothing but a process
        /// running as the daemon's own uid can ever read this payload.
        /// The redaction the rest of keyhog relies on is applied
        /// client-side, after these bytes have already crossed the socket
        /// under that 0600 guarantee - never trust this field to be
        /// redacted on the wire.
        matches: Vec<RawMatch>,
        /// Wire-v2: scanner-side example suppression count. Defaults
        /// to 0 for back-compat with v1 servers (serde default).
        #[serde(default)]
        engine_example_suppressions: u64,
        /// Wire-v2: per-decision dogfood events captured on the
        /// daemon side. Empty unless the daemon was started with
        /// `KEYHOG_DOGFOOD=1`.
        #[serde(default)]
        dogfood_events: Vec<DogfoodEvent>,
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
