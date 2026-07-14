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
use std::collections::BTreeMap;

/// Bump on any incompatible wire-format change. Server replies with
/// its supported version and build/corpus identity in the [`Hello`] handshake;
/// scan clients refuse a daemon whose identity does not match.
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
/// * v2 extension - `ScanResults` gained source coverage gaps so
///   daemon-side skipped input cannot report clean.
/// * v3 - `Hello` binds the daemon to its Git build and canonical detector
///   rules digest, not merely the package version. The original suppression,
///   dogfood-event, and coverage fields are required; malformed frames cannot
///   synthesize clean-looking zero values.
/// * v4 - `ScanResults` carries exact static-recovery rejection aggregates and
///   the omitted-detail count. These cannot default because reconstructing exact
///   totals from a bounded detail list would silently undercount.
/// * v5 - `Hello` names the daemon-owned backend policy so scan clients consent
///   to an observable autoroute or forced diagnostic route instead of accepting
///   an undisclosed startup override.
pub const WIRE_VERSION: u32 = 5;

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
    ScanText {
        path: Option<String>,
        text: String,
        dogfood: bool,
    },
    /// Scan a filesystem path (a regular file) using the daemon's
    /// pre-compiled scanner. Path resolution happens on the daemon
    /// side; relative paths resolve against `working_dir`.
    ScanPath {
        path: String,
        working_dir: Option<String>,
        dogfood: bool,
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
        git_hash: String,
        detector_rules_digest: String,
        /// `autoroute` or the canonical label of the backend forced at daemon
        /// startup (`gpu-region-presence`, `simd-regex`, or `cpu-fallback`).
        backend_policy: String,
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
    /// `dogfood_events` and its exact aggregates are populated only when the
    /// request enables dogfood capture. The daemon installs one request-scoped
    /// telemetry owner, so concurrent clients cannot share detail state.
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
        /// Scanner-side example suppression count. Required since wire v3; the
        /// strict Hello handshake rejects older peers before scan traffic.
        engine_example_suppressions: u64,
        /// Per-decision dogfood events captured on the daemon side.
        dogfood_events: Vec<DogfoodEvent>,
        /// Exact per-reason static-recovery rejection-attempt counts. Populated
        /// only when this request enables dogfood capture. Counts remain
        /// complete after the bounded detail buffer fills.
        static_recovery_rejections: BTreeMap<String, u64>,
        /// Number of daemon-side detail events omitted after the bounded trace
        /// filled. Required in wire v4 so a client never invents a zero count.
        dogfood_detail_events_dropped: u64,
        /// Source coverage gaps recorded inside the daemon
        /// while expanding a `ScanPath` request. The client process cannot read
        /// the daemon's process-local counters directly, so missing this field
        /// used to let binary/unreadable/truncated daemon input exit clean.
        source_coverage_gaps: SourceCoverageGaps,
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceCoverageGaps {
    pub over_max_size: usize,
    pub binary: usize,
    pub unreadable: usize,
    pub git_object_unreadable: usize,
    pub archive_truncated: usize,
    pub binary_section_name_unresolved: usize,
    pub source_truncated: usize,
    pub structured_source_parse_failures: usize,
    pub archive_duplicate_scan_unavailable: usize,
    pub git_lfs_pointer: usize,
}

impl SourceCoverageGaps {
    pub fn total(self) -> usize {
        self.over_max_size
            + self.binary
            + self.unreadable
            + self.git_object_unreadable
            + self.archive_truncated
            + self.binary_section_name_unresolved
            + self.source_truncated
            + self.structured_source_parse_failures
            + self.archive_duplicate_scan_unavailable
            + self.git_lfs_pointer
    }

    pub fn is_empty(self) -> bool {
        self.total() == 0
    }
}

/// One-word kind label for a daemon [`Response`]. Use this in user-facing
/// protocol errors instead of `Debug`: response payloads can contain scanner
/// results and therefore credential-shaped data.
pub(crate) fn response_kind(response: &Response) -> &'static str {
    match response {
        Response::Hello { .. } => "Hello",
        Response::Health { .. } => "Health",
        Response::ScanResults { .. } => "ScanResults",
        Response::Shutdown => "Shutdown",
        Response::Error { .. } => "Error",
    }
}
