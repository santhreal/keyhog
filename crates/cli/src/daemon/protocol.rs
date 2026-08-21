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

use keyhog_core::{
    CompanionMap, CredentialHash, MatchLocation, RawMatch, SensitiveString, Severity,
};
use keyhog_scanner::telemetry::{DogfoodEvent, StaticRecoveryStatus};
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
/// * v6 - scan results and health expose complete backend recovery plus the
///   daemon's last route fault; recovered requests can never look like clean
///   no-fault execution to clients.
/// * v7 - Hello and health bind persistent warm readiness to the exact
///   autoroute engine, GPU artifact, executable, detector, and resolved-config
///   identities. A daemon with incomplete backend initialization reports the
///   missing engines and cannot satisfy a scan handshake.
/// * v8 - `ScanResults` carries the exact static-recovery disposition totals
///   (`supported`, `unsupported`, and `erroneous`) as well as per-reason
///   rejections, so daemon routing conserves the complete recovery receipt.
/// * v9 - adds an explicit bounded mass-service transaction. The client acquires
///   directory, Git, archive, binary, remote, and cloud sources, then streams
///   authenticated `Chunk` batches while one server-side fragment-cache lease
///   prevents cross-job state contamination.
/// * v10 - `Hello` advertises a mass-service GPU-majority contract. Clients
///   validate the terminal execution receipt and fail closed when GPU did not
///   process more than half of all non-empty payload bytes.
/// * v11 - mass services can acquire local filesystem roots directly. The wire
///   carries only path/config metadata while bounded source batches remain in
///   the daemon process.
/// * v12 - scan requests carry an opt-in `profile` flag and `ScanResults`
///   carries a bounded per-request profile: a daemon-unique request id, wall
///   time, per-stage call/elapsed aggregates, and explicit event loss counts.
///   Each profiled request runs inside an isolated profiling runtime in the
///   daemon, so concurrent requests never share measurements. Old-version
///   handling is unchanged: the Hello handshake compares `WIRE_VERSION` on
///   both ends and a mismatched peer is refused before any scan traffic, so a
///   v11 client never parses a v12 frame (and vice versa).
/// * v13 - adds the guard commit transaction: `GuardCommitBegin`,
///   `GuardCommitPlan`, `GuardCommitBlob`, `GuardCommitBlobAck`,
///   `GuardCommitFinish`, and `GuardCommitReceipt` frames for exact
///   staged-object authorization, plus `GuardAdd`, `GuardRemove`,
///   `GuardStatus`, and `GuardReconcile` root control frames. The
///   client validates conservation of object count and bytes and
///   reacquires the index fingerprint before accepting the receipt.
/// * v14 - lets daemon-local filesystem scans consume and publish spec-bound
///   Merkle state, carry trusted skip evidence, and stream bounded batches
///   after one drain request.
/// * v15 - raw scanner findings carry a validated evidence verdict. Guard
///   receipts carry exact protected findings and the default-policy blocking
///   count so daemon, staged-guard, and one-shot scans preserve finding output
///   and evidence-policy exits.
/// * v16 - continuous guard transition feed and event log wire frames
///   (`GuardFeed`, `GuardFeedResult`) expose recent state transitions with
///   causal attribution across registered roots, and guard status replies add
///   filesystem authority probe results, watcher backend details, and periodic
///   scrub intervals.
pub(crate) const WIRE_VERSION: u32 = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WarmBackendIdentity {
    pub engine: String,
    pub gpu_artifact: Option<String>,
    pub binary_sha256: String,
    pub detector_rules_digest: String,
    pub config_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WarmBackendStatus {
    pub ready: bool,
    pub daemon_generation: String,
    pub identity: WarmBackendIdentity,
    pub required_backends: Vec<String>,
    pub initialized_backends: Vec<String>,
    pub reason: Option<String>,
    pub repair_command: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MassScanStats {
    pub batches: u64,
    pub chunks: u64,
    pub bytes: u64,
    pub gpu_batches: u64,
    pub gpu_chunks: u64,
    pub gpu_bytes: u64,
    pub duration_ms: u64,
}

impl MassScanStats {
    pub(crate) fn gpu_is_primary(self) -> bool {
        self.bytes > 0 && self.gpu_bytes > self.bytes.saturating_sub(self.gpu_bytes)
    }
}

/// One per-stage aggregate inside a daemon request profile. The stage
/// vocabulary is the fixed `keyhog_profile::Stage` enum, so names carry no
/// input data and the payload is privacy-safe by construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileStageMeasurement {
    pub stage: String,
    pub calls: u64,
    pub elapsed_ns: u64,
}

/// Bounded, privacy-safe profile of one daemon-served scan request. Carries
/// no paths (beyond what `ScanResults` already carries) and no credentials:
/// only the server-assigned request id, one wall-clock total, per-stage
/// aggregates bounded by the fixed `keyhog_profile::Stage` enum (25 entries),
/// and exact event loss counts so dropped detail is never silent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestProfile {
    /// Server-assigned identity: the daemon generation string from
    /// [`WarmBackendStatus`] plus a process-atomic per-request sequence.
    pub request_id: String,
    pub wall_time_ns: u64,
    pub stages: Vec<ProfileStageMeasurement>,
    pub dropped_span_events: u64,
    pub dropped_point_events: u64,
    pub dropped_annotations: u64,
    pub sampled_out_events: u64,
}

/// Maximum length of a single framed message body. 64 MiB ceiling
/// matches `MAX_SCAN_CHUNK_BYTES * 64` so a chunk batch fits, but
/// bounds the recv buffer so a hostile client can't OOM the daemon
/// by lying about the length prefix.
pub(crate) const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;
/// Raw UTF-8 payload accepted in one mass-service batch. JSON escaping can
/// expand a byte to six bytes, so 8 MiB keeps the worst-case body below the
/// 64 MiB frame ceiling with metadata and framing headroom.
pub(crate) const MASS_BATCH_BYTES: usize = 8 * 1024 * 1024;
/// Bound metadata and allocation overhead even for many tiny source chunks.
pub(crate) const MASS_BATCH_CHUNKS: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(crate) enum Request {
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
        /// Opt-in per-request profiling. The daemon isolates the scan in its
        /// own profiling runtime and returns the measurements in
        /// [`Response::ScanResults::profile`].
        profile: bool,
    },
    /// Scan a filesystem path (a regular file) using the daemon's
    /// pre-compiled scanner. Path resolution happens on the daemon
    /// side; relative paths resolve against `working_dir`.
    ScanPath {
        path: String,
        working_dir: Option<String>,
        dogfood: bool,
        /// Opt-in per-request profiling, same contract as [`Request::ScanText`].
        profile: bool,
    },
    /// Begin one bounded mass scan. The server acquires exclusive ownership of
    /// fragment-reassembly state until `MassEnd` or connection teardown.
    MassBegin { dogfood: bool, profile: bool },
    /// Scan one client-acquired source batch inside an active mass transaction.
    /// The raw payload and chunk count are independently bounded.
    MassBatch {
        #[serde(with = "protected_chunks")]
        chunks: Vec<keyhog_core::Chunk>,
    },
    /// Start daemon-local acquisition for one filesystem root. Only path and
    /// source policy cross the socket; file payload bytes stay in the daemon.
    MassFilesystemBegin {
        root: String,
        max_file_size: u64,
        ignore_paths: Vec<String>,
        respect_default_excludes: bool,
        reader_threads: Option<usize>,
        incremental_cache: Option<String>,
    },
    /// Scan and stream every bounded batch from the active daemon-local
    /// filesystem source. The terminal response is `MassFilesystemComplete`.
    MassFilesystemDrain,
    /// Finish the transaction, clear fragment state, and release the worker.
    MassEnd,
    /// Liveness + cheap status (uptime, scans served, detector count).
    Health,
    /// Graceful shutdown - daemon flushes in-flight scans, drops the
    /// socket, exits. The client side is `keyhog daemon stop`.
    Shutdown,
    // ── Guard commit transaction ──────────────────────────────────────
    /// Begin a guard commit transaction. The server checks the staged
    /// manifest against the clean attestation cache and returns a plan
    /// naming which blobs need payload streaming.
    GuardCommitBegin {
        /// Repository identity (worktree root path).
        repo_path: String,
        /// Index fingerprint from the staged manifest.
        index_fingerprint: String,
        /// Git hash algorithm.
        hash_algorithm: String,
        /// Staged manifest entries (path, OID, size, kind, mode).
        entries: Vec<GuardWireManifestEntry>,
    },
    /// Stream one blob payload for a previously planned transaction.
    /// Only blobs the server named in `GuardCommitPlan::required_blob_oids`
    /// are sent; clean-hit blobs are never transmitted.
    GuardCommitBlob {
        /// Transaction ID from the plan.
        transaction_id: u64,
        /// Blob object ID (hex).
        blob_oid: String,
        /// Object size in bytes.
        object_size: u64,
        /// Payload bytes (bounded by MAX_FRAME_BYTES).
        #[serde(with = "protected_chunks")]
        payload: Vec<keyhog_core::Chunk>,
    },
    /// Finish the transaction. The server validates conservation and
    /// reacquires the index fingerprint, then returns the receipt.
    GuardCommitFinish {
        /// Transaction ID from the plan.
        transaction_id: u64,
        /// Total objects the client streamed.
        client_objects_streamed: u64,
        /// Total bytes the client streamed.
        client_bytes_streamed: u64,
    },
    // ── Guard root control ─────────────────────────────────────────────
    /// Register a root for continuous guard protection.
    GuardAdd {
        /// Canonical root path.
        root: String,
        /// Repository or filesystem mode.
        mode: String,
    },
    /// Remove a root from guard protection and delete its persisted state.
    GuardRemove {
        /// Canonical root path.
        root: String,
    },
    /// Query the current status of a guarded root.
    GuardStatus {
        /// Canonical root path.
        root: String,
    },
    /// Force a full reconciliation of a guarded root.
    GuardReconcile {
        /// Canonical root path.
        root: String,
    },
    /// List all registered guard roots.
    GuardList,
    // ── Guard transition feed ──────────────────────────────────────────
    /// Query the continuous transition feed / event log across roots.
    GuardFeed {
        /// Optional root filter (canonical path).
        root: Option<String>,
        /// Maximum transitions to return (bounded, default 50).
        limit: Option<usize>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Response {
    Hello {
        wire_version: u32,
        keyhog_version: String,
        git_hash: String,
        detector_rules_digest: String,
        /// `autoroute`, `autoroute-degraded` for persisted route quarantine, or
        /// the canonical label of a backend forced at daemon startup.
        backend_policy: String,
        detector_count: usize,
        uptime_secs: u64,
        warm_backend: WarmBackendStatus,
        /// Whether this daemon was explicitly started as a mass-service worker.
        mass_service: bool,
        /// Whether mass scans must prove that GPU processed most payload bytes.
        mass_gpu_primary_required: bool,
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
    /// Exact static-recovery aggregates are always populated; bounded
    /// `dogfood_events` detail is populated only when requested. Each request
    /// owns its telemetry snapshot, so concurrent clients cannot share state.
    ScanResults {
        path: Option<String>,
        /// Security: each `RawMatch` carries the unredacted plaintext
        /// credential. Serialization is confined to this crate and occurs only
        /// on a connected Unix stream after the client and server have verified
        /// the peer uid. The socket's `0600` mode and private parent directory
        /// are additional access controls, not peer authentication. Redaction
        /// remains client-side, after these bytes cross that authenticated
        /// local connection.
        #[serde(with = "protected_raw_matches")]
        matches: Vec<RawMatch>,
        /// Scanner-side example suppression count. Required since wire v3; the
        /// strict Hello handshake rejects older peers before scan traffic.
        engine_example_suppressions: u64,
        /// Per-decision dogfood events captured on the daemon side.
        dogfood_events: Vec<DogfoodEvent>,
        /// Exact, always-on per-reason static-recovery rejection counts. These
        /// remain complete regardless of dogfood detail capture or buffer
        /// exhaustion.
        static_recovery_rejections: BTreeMap<String, u64>,
        /// Exact disposition totals for static recovery. Required since wire v8;
        /// an absent value must not silently become a clean zero.
        static_recovery_status: StaticRecoveryStatus,
        /// Number of daemon-side detail events omitted after the bounded trace
        /// filled. Required in wire v4 so a client never invents a zero count.
        dogfood_detail_events_dropped: u64,
        /// Source coverage gaps recorded inside the daemon
        /// while expanding a `ScanPath` request. The client process cannot read
        /// the daemon's process-local counters directly, so missing this field
        /// used to let binary/unreadable/truncated daemon input exit clean.
        source_coverage_gaps: SourceCoverageGaps,
        /// Exact completed recovery for this request after an authenticated
        /// selected route faulted. Invalid autoroute state never creates a
        /// recovery receipt. `None` means no recovery.
        backend_recovery: RequiredOption<BackendRecoveryStatus>,
        /// Isolated profile of this exact request. Present only when the
        /// request carried `profile: true`; `None` means the daemon recorded
        /// no per-request measurements. Required since wire v12.
        profile: RequiredOption<RequestProfile>,
    },
    /// The mass-service fragment-state lease is held and batches may follow.
    MassReady,
    /// Daemon-local filesystem acquisition is ready for bounded pulls.
    MassFilesystemReady,
    /// One daemon-local filesystem root drained. Coverage gaps and trusted
    /// unchanged-file skips remain explicit.
    MassFilesystemComplete {
        source_coverage_gaps: SourceCoverageGaps,
        skipped_unchanged: usize,
    },
    /// The filesystem scan completed, but its incremental generation could not
    /// be published. Clients classify this as a system I/O failure.
    MassFilesystemIncrementalError { message: String },
    /// The mass transaction completed and released its scanner-state lease.
    MassComplete { stats: MassScanStats },
    Health {
        uptime_secs: u64,
        scans_served: u64,
        active_scans: u32,
        detector_count: usize,
        backend_recoveries: u64,
        last_backend_fault: Option<BackendRecoveryStatus>,
        /// Guard: total registered roots.
        guard_roots_registered: u64,
        /// Guard: roots in Current state.
        guard_roots_current: u64,
        /// Guard: roots in Blocked state.
        guard_roots_blocked: u64,
        /// Guard: roots in Degraded state.
        guard_roots_degraded: u64,
        /// Guard: active commit transactions.
        guard_active_transactions: u64,
        warm_backend: WarmBackendStatus,
    },
    /// Anything that went wrong on the server side. Connection stays
    /// open so the client can retry with a different request.
    Error { message: String },
    /// Acknowledgement for `Shutdown`. The daemon closes the socket
    /// after sending this; the client should not write again.
    Shutdown,
    // ── Guard commit transaction ──────────────────────────────────────
    /// Plan for a guard commit transaction: which blobs are clean hits
    /// (no payload needed) and which need streaming.
    GuardCommitPlan {
        /// Server-assigned transaction ID.
        transaction_id: u64,
        /// Object OIDs that are clean hits (no payload streaming needed).
        clean_hits: Vec<String>,
        /// Object OIDs that need payload streaming.
        required_blob_oids: Vec<String>,
        /// Maximum bytes per blob frame.
        max_blob_bytes: u64,
    },
    /// Acknowledgement that a streamed blob was scanned. Distinct from
    /// `GuardCommitPlan` so the client can distinguish a per-blob ack
    /// from a new plan with empty required OIDs.
    GuardCommitBlobAck {
        /// Transaction ID from the plan.
        transaction_id: u64,
        /// Blob object ID that was scanned (hex).
        blob_oid: String,
        /// Bytes accounted for this blob.
        bytes_scanned: u64,
        /// Findings count for this blob.
        findings_count: u64,
    },
    /// Terminal receipt for a guard commit transaction. The client
    /// validates conservation and reacquires the index fingerprint
    /// before accepting this receipt.
    GuardCommitReceipt {
        /// Objects requested in the transaction.
        objects_requested: u64,
        /// Objects served from the clean attestation cache.
        objects_hit: u64,
        /// Objects scanned.
        objects_scanned: u64,
        /// Objects skipped (deletions, symlinks, submodules).
        objects_skipped: u64,
        /// Total bytes requested.
        bytes_requested: u64,
        /// Total bytes served from cache.
        bytes_hit: u64,
        /// Total bytes scanned.
        bytes_scanned: u64,
        /// Number of unsuppressed findings.
        findings_count: u64,
        /// Exact findings carried through the protected daemon transport.
        #[serde(with = "protected_raw_matches")]
        findings: Vec<RawMatch>,
        /// Findings that block the default evidence policy.
        blocking_findings_count: u64,
        /// Number of coverage gaps.
        coverage_gaps: u64,
        /// Terminal root state label.
        terminal_state: String,
        /// Terminal event sequence.
        terminal_sequence: u64,
    },
    // ── Guard root control ─────────────────────────────────────────────
    /// Root registered successfully after initial reconciliation.
    GuardAdded {
        /// Canonical root path.
        root: String,
        /// Terminal root state label.
        state: String,
        /// Terminal event sequence.
        terminal_sequence: u64,
    },
    /// Root removed from guard protection.
    GuardRemoved,
    /// Current status of a guarded root.
    GuardStatusResult {
        /// Canonical root path.
        root: String,
        /// Mode label (repo or filesystem).
        mode: String,
        /// Current state label.
        state: String,
        /// Backing filesystem type (Row 132).
        filesystem_type: String,
        /// Whether the filesystem is authoritative for change events (Row 132).
        filesystem_authoritative: bool,
        /// Reason if unauthoritative (Row 132).
        filesystem_unauthoritative_reason: Option<String>,
        /// Effective periodic scrub interval in seconds (Row 132).
        scrub_interval_secs: u64,
        /// Terminal event sequence.
        terminal_sequence: u64,
        /// Accepted event sequence (events received from the watcher).
        accepted_event_sequence: u64,
        /// Completed event sequence (events fully processed).
        completed_event_sequence: u64,
        /// Pending event count.
        pending_events: u64,
        /// Files scanned in the current receipt.
        files_scanned: u64,
        /// Bytes scanned in the current receipt.
        bytes_scanned: u64,
        /// Clean attestation hits.
        attestation_hits: u64,
        /// Clean attestation misses.
        attestation_misses: u64,
        /// Findings count (without secret values).
        findings_count: u64,
        /// Coverage gaps count.
        coverage_gaps: u64,
        /// Unix timestamp of the initial reconciliation completion.
        initial_reconciliation_time: Option<u64>,
        /// Unix timestamp of the last reconciliation completion.
        last_reconciliation_time: Option<u64>,
        /// Scanner residency label.
        scanner_residency: String,
        /// Watcher backend identifier label (Row 123).
        #[serde(default)]
        watcher_backend: String,
        /// Watcher backend latency tier classification (Row 123).
        #[serde(default)]
        watcher_latency_tier: String,
        /// Watcher polling interval in milliseconds, if polling (Row 123).
        #[serde(default)]
        watcher_poll_interval_ms: Option<u64>,
        /// Backend route label used for the last scan.
        backend_route_label: String,
        /// Build identity short digest (first 12 hex chars).
        build_identity_short: String,
        /// Detector digest short (first 12 hex chars).
        detector_digest_short: String,
        /// Suppression digest short (first 12 hex chars).
        suppression_digest_short: String,
        /// Config digest short (first 12 hex chars).
        config_digest_short: String,
        /// Autoroute evidence status label.
        autoroute_evidence_status: String,
        /// Guard store schema version.
        store_schema_version: u32,
        /// Guard store path (or empty if in-memory only).
        store_path: String,
        /// Exact repair command.
        repair_command: String,
        /// Recent state transitions with causes for this root.
        #[serde(default)]
        recent_transitions: Vec<GuardTransitionWireEntry>,
    },
    /// Continuous transition feed result with causal attribution.
    GuardFeedResult {
        /// Recent state transitions in chronological order.
        transitions: Vec<GuardTransitionWireEntry>,
    },
    /// Reconciliation started for a guarded root.
    GuardReconcileStarted {
        /// Canonical root path.
        root: String,
    },
    /// List of all registered guard roots with their states.
    GuardListResult {
        /// All registered roots, each with path, mode, and state.
        roots: Vec<GuardListEntry>,
    },
}

/// Borrowed fields used to prove a guard receipt fits one protocol frame before
/// the transaction is consumed.
pub(crate) struct GuardCommitReceiptWireFields<'a> {
    pub objects_requested: u64,
    pub objects_hit: u64,
    pub objects_scanned: u64,
    pub objects_skipped: u64,
    pub bytes_requested: u64,
    pub bytes_hit: u64,
    pub bytes_scanned: u64,
    pub findings_count: u64,
    pub findings: &'a [RawMatch],
    pub blocking_findings_count: u64,
    pub coverage_gaps: u64,
    pub terminal_state: &'a str,
    pub terminal_sequence: u64,
}

/// Return the exact JSON body length for a protected guard receipt without
/// allocating a second findings payload.
pub(crate) fn guard_commit_receipt_wire_len(
    fields: GuardCommitReceiptWireFields<'_>,
) -> serde_json::Result<usize> {
    #[derive(Serialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum BorrowedResponse<'a> {
        GuardCommitReceipt {
            objects_requested: u64,
            objects_hit: u64,
            objects_scanned: u64,
            objects_skipped: u64,
            bytes_requested: u64,
            bytes_hit: u64,
            bytes_scanned: u64,
            findings_count: u64,
            #[serde(with = "protected_raw_matches")]
            findings: &'a [RawMatch],
            blocking_findings_count: u64,
            coverage_gaps: u64,
            terminal_state: &'a str,
            terminal_sequence: u64,
        },
    }

    #[derive(Default)]
    struct ByteCounter(usize);

    impl std::io::Write for ByteCounter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("guard receipt length overflow"))?;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = ByteCounter::default();
    serde_json::to_writer(
        &mut counter,
        &BorrowedResponse::GuardCommitReceipt {
            objects_requested: fields.objects_requested,
            objects_hit: fields.objects_hit,
            objects_scanned: fields.objects_scanned,
            objects_skipped: fields.objects_skipped,
            bytes_requested: fields.bytes_requested,
            bytes_hit: fields.bytes_hit,
            bytes_scanned: fields.bytes_scanned,
            findings_count: fields.findings_count,
            findings: fields.findings,
            blocking_findings_count: fields.blocking_findings_count,
            coverage_gaps: fields.coverage_gaps,
            terminal_state: fields.terminal_state,
            terminal_sequence: fields.terminal_sequence,
        },
    )?;
    Ok(counter.0)
}

/// One entry in the staged manifest sent over the wire in
/// `GuardCommitBegin`. Carries no payload bytes, only identity metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardWireManifestEntry {
    /// Path bytes as hex-encoded UTF-8 (non-UTF-8 paths are hex-escaped).
    pub path: String,
    /// Entry kind label: "file", "symlink", "submodule", "deletion".
    pub kind: String,
    /// Staged blob object ID (hex). Empty for deletions.
    pub object_oid: String,
    /// Exact object size in bytes.
    pub object_size: u64,
    /// Raw file mode from the index.
    pub raw_mode: u32,
}

/// One state transition entry in a guard transition feed or status result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardTransitionWireEntry {
    /// Canonical root path.
    pub root: String,
    /// Global transition sequence.
    pub sequence: u64,
    /// Unix timestamp (seconds) when the transition occurred.
    pub timestamp: u64,
    /// State before transition.
    pub from_state: String,
    /// State after transition.
    pub to_state: String,
    /// Transition event label.
    pub event: String,
    /// Causal attribution / reason for the transition.
    pub cause: String,
}
/// One root entry in a `GuardListResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GuardListEntry {
    /// Canonical root path.
    pub root: String,
    /// Mode label: "repo" or "filesystem".
    pub mode: String,
    /// Current state label.
    pub state: String,
    /// Terminal event sequence.
    pub terminal_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BackendRecoveryStatus {
    pub failed_backend: String,
    pub recovery_backend: String,
    pub recovered_ranges: Vec<RecoveredInputRangeStatus>,
    pub recovered_chunks: usize,
    pub recovered_bytes: u64,
    pub reason: String,
}
/// Like `Option`, but the field must be present on the wire. The `None`
/// variant serializes to `null` and deserializes from `null`; an absent
/// field is a deserialization error so older peers cannot silently downgrade
/// a v6 `ScanResults` frame to a no-fault execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RequiredOption<T> {
    None,
    Some(T),
}

#[cfg(test)]
impl<T> RequiredOption<T> {
    pub(crate) fn is_none(&self) -> bool {
        matches!(self, RequiredOption::None)
    }

    pub(crate) fn expect(self, msg: &str) -> T {
        match self {
            RequiredOption::Some(v) => v,
            RequiredOption::None => panic!("{msg}"),
        }
    }
}

impl<T> From<Option<T>> for RequiredOption<T> {
    fn from(opt: Option<T>) -> Self {
        opt.map_or(RequiredOption::None, RequiredOption::Some)
    }
}

impl<T> From<RequiredOption<T>> for Option<T> {
    fn from(req: RequiredOption<T>) -> Self {
        match req {
            RequiredOption::None => None,
            RequiredOption::Some(v) => Some(v),
        }
    }
}

impl<T: Serialize> Serialize for RequiredOption<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            RequiredOption::None => serializer.serialize_none(),
            RequiredOption::Some(v) => v.serialize(serializer),
        }
    }
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for RequiredOption<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RequiredOptionVisitor<T> {
            marker: std::marker::PhantomData<T>,
        }
        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for RequiredOptionVisitor<T> {
            type Value = RequiredOption<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a required optional value")
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(RequiredOption::None)
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(RequiredOption::None)
            }
            fn visit_map<M>(self, map: M) -> Result<Self::Value, M::Error>
            where
                M: serde::de::MapAccess<'de>,
            {
                let de = serde::de::value::MapAccessDeserializer::new(map);
                T::deserialize(de).map(RequiredOption::Some)
            }
            fn visit_seq<S>(self, seq: S) -> Result<Self::Value, S::Error>
            where
                S: serde::de::SeqAccess<'de>,
            {
                let de = serde::de::value::SeqAccessDeserializer::new(seq);
                T::deserialize(de).map(RequiredOption::Some)
            }
        }
        deserializer.deserialize_any(RequiredOptionVisitor {
            marker: std::marker::PhantomData,
        })
    }
}

impl<T> Default for RequiredOption<T> {
    fn default() -> Self {
        RequiredOption::None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RecoveredInputRangeStatus {
    pub chunk_index: usize,
    pub byte_start: usize,
    pub byte_end: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SourceCoverageGaps {
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
    /// Client-side source acquisition failed or produced an explicit source
    /// error. This is always a FAIL-class gap.
    pub source_failed: usize,
}

impl SourceCoverageGaps {
    pub(crate) fn total(self) -> usize {
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
            + self.source_failed
    }

    /// CoverageGapKind FAIL set only (KH-1347 / KH-1368). WARN skips
    /// (binary, over_max_size) do not flip incomplete exit 13.
    pub(crate) fn fail_class_total(self) -> usize {
        self.unreadable
            + self.git_object_unreadable
            + self.archive_truncated
            + self.binary_section_name_unresolved
            + self.source_truncated
            + self.structured_source_parse_failures
            + self.archive_duplicate_scan_unavailable
            + self.git_lfs_pointer
            + self.source_failed
    }

    pub(crate) fn is_empty(self) -> bool {
        self.total() == 0
    }

    #[cfg(test)]
    pub(crate) fn fail_class_empty(self) -> bool {
        self.fail_class_total() == 0
    }
}

/// Explicit plaintext adapter for source chunks crossing the authenticated,
/// same-uid Unix socket. `SensitiveString` rejects implicit serialization.
mod protected_chunks {
    use keyhog_core::{Chunk, ChunkMetadata, SensitiveString};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[derive(Serialize)]
    struct ChunkRef<'a> {
        #[serde(serialize_with = "serialize_sensitive")]
        data: &'a SensitiveString,
        metadata: &'a ChunkMetadata,
    }

    #[derive(Deserialize)]
    struct ChunkOwned {
        data: String,
        metadata: ChunkMetadata,
    }

    pub(super) fn serialize<S>(chunks: &[Chunk], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(chunks.len()))?;
        for chunk in chunks {
            sequence.serialize_element(&ChunkRef {
                data: &chunk.data,
                metadata: &chunk.metadata,
            })?;
        }
        sequence.end()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Chunk>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<ChunkOwned>::deserialize(deserializer).map(|chunks| {
            chunks
                .into_iter()
                .map(|chunk| Chunk {
                    data: chunk.data.into(),
                    metadata: chunk.metadata,
                })
                .collect()
        })
    }

    fn serialize_sensitive<S>(value: &&SensitiveString, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(value.as_str())
    }
}

/// Explicit plaintext adapter for scanner matches crossing the authenticated,
/// same-uid Unix socket. `RawMatch` refuses implicit plaintext serialization,
/// and the temporary owned credential string moves into zeroized storage.
mod protected_raw_matches {
    use super::{CompanionMap, CredentialHash, MatchLocation, RawMatch, SensitiveString, Severity};
    use serde::ser::{SerializeMap, SerializeSeq};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Serialize)]
    struct DaemonRawMatchRef<'a> {
        detector_id: &'a str,
        detector_name: &'a str,
        service: &'a str,
        severity: Severity,
        #[serde(serialize_with = "serialize_sensitive")]
        credential: &'a SensitiveString,
        credential_hash: CredentialHash,
        #[serde(serialize_with = "serialize_companions")]
        companions: &'a CompanionMap,
        location: &'a MatchLocation,
        #[serde(skip_serializing_if = "Option::is_none")]
        entropy: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        confidence: Option<f64>,
        evidence: keyhog_core::EvidenceVerdict,
    }

    #[derive(Deserialize)]
    struct DaemonRawMatchOwned {
        detector_id: String,
        detector_name: String,
        service: String,
        severity: Severity,
        #[serde(deserialize_with = "deserialize_sensitive")]
        credential: SensitiveString,
        credential_hash: CredentialHash,
        companions: HashMap<String, String>,
        location: MatchLocation,
        entropy: Option<f64>,
        confidence: Option<f64>,
        evidence: keyhog_core::EvidenceVerdict,
    }

    impl From<DaemonRawMatchOwned> for RawMatch {
        fn from(wire: DaemonRawMatchOwned) -> Self {
            Self {
                detector_id: Arc::from(wire.detector_id),
                detector_name: Arc::from(wire.detector_name),
                service: Arc::from(wire.service),
                severity: wire.severity,
                credential: wire.credential,
                credential_hash: wire.credential_hash,
                companions: wire
                    .companions
                    .into_iter()
                    .map(|(name, value)| (Arc::from(name), value))
                    .collect(),
                location: wire.location,
                entropy: wire.entropy,
                confidence: wire.confidence,
                evidence: wire.evidence,
            }
        }
    }

    pub(super) fn serialize<S>(matches: &[RawMatch], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(matches.len()))?;
        for raw_match in matches {
            sequence.serialize_element(&DaemonRawMatchRef {
                detector_id: raw_match.detector_id.as_ref(),
                detector_name: raw_match.detector_name.as_ref(),
                service: raw_match.service.as_ref(),
                severity: raw_match.severity,
                credential: &raw_match.credential,
                credential_hash: raw_match.credential_hash,
                companions: &raw_match.companions,
                location: &raw_match.location,
                entropy: raw_match.entropy,
                confidence: raw_match.confidence,
                evidence: raw_match.evidence,
            })?;
        }
        sequence.end()
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<RawMatch>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<DaemonRawMatchOwned>::deserialize(deserializer)
            .map(|matches| matches.into_iter().map(RawMatch::from).collect())
    }

    fn serialize_sensitive<S>(
        credential: &&SensitiveString, // keyhog:ignore detector=generic-keyword-secret
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(credential.as_str())
    }

    fn deserialize_sensitive<'de, D>(deserializer: D) -> Result<SensitiveString, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(SensitiveString::from)
    }

    fn serialize_companions<S>(companions: &&CompanionMap, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(companions.len()))?;
        for (name, value) in companions.iter() {
            map.serialize_entry(name.as_ref(), value)?;
        }
        map.end()
    }
}

/// One-word kind label for a daemon [`Request`]. Never format a request with
/// `Debug` because mass batches and text requests contain credential-shaped data.
pub(crate) fn request_kind(request: &Request) -> &'static str {
    match request {
        Request::Hello => "Hello",
        Request::ScanText { .. } => "ScanText",
        Request::ScanPath { .. } => "ScanPath",
        Request::MassBegin { .. } => "MassBegin",
        Request::MassBatch { .. } => "MassBatch",
        Request::MassFilesystemBegin { .. } => "MassFilesystemBegin",
        Request::MassFilesystemDrain => "MassFilesystemDrain",
        Request::MassEnd => "MassEnd",
        Request::Health => "Health",
        Request::Shutdown => "Shutdown",
        Request::GuardCommitBegin { .. } => "GuardCommitBegin",
        Request::GuardCommitBlob { .. } => "GuardCommitBlob",
        Request::GuardCommitFinish { .. } => "GuardCommitFinish",
        Request::GuardAdd { .. } => "GuardAdd",
        Request::GuardRemove { .. } => "GuardRemove",
        Request::GuardStatus { .. } => "GuardStatus",
        Request::GuardReconcile { .. } => "GuardReconcile",
        Request::GuardList => "GuardList",
        Request::GuardFeed { .. } => "GuardFeed",
    }
}

/// All 19 daemon request kinds.
pub(crate) const ALL_REQUEST_KINDS: &[&str] = &[
    "Hello",
    "ScanText",
    "ScanPath",
    "MassBegin",
    "MassBatch",
    "MassFilesystemBegin",
    "MassFilesystemDrain",
    "MassEnd",
    "Health",
    "Shutdown",
    "GuardCommitBegin",
    "GuardCommitBlob",
    "GuardCommitFinish",
    "GuardAdd",
    "GuardRemove",
    "GuardStatus",
    "GuardReconcile",
    "GuardList",
    "GuardFeed",
];

/// Sample request instance for every known request kind.
pub(crate) fn sample_request_for_kind(kind: &str) -> Option<Request> {
    match kind {
        "Hello" => Some(Request::Hello),
        "ScanText" => Some(Request::ScanText {
            path: None,
            text: "test sample content".to_string(),
            dogfood: false,
            profile: false,
        }),
        "ScanPath" => Some(Request::ScanPath {
            path: "/dev/null".to_string(),
            working_dir: None,
            dogfood: false,
            profile: false,
        }),
        "MassBegin" => Some(Request::MassBegin {
            dogfood: false,
            profile: false,
        }),
        "MassBatch" => Some(Request::MassBatch { chunks: vec![] }),
        "MassFilesystemBegin" => Some(Request::MassFilesystemBegin {
            root: "/tmp".to_string(),
            max_file_size: 1024 * 1024,
            ignore_paths: vec![],
            respect_default_excludes: true,
            reader_threads: None,
            incremental_cache: None,
        }),
        "MassFilesystemDrain" => Some(Request::MassFilesystemDrain),
        "MassEnd" => Some(Request::MassEnd),
        "Health" => Some(Request::Health),
        "Shutdown" => Some(Request::Shutdown),
        "GuardCommitBegin" => Some(Request::GuardCommitBegin {
            repo_path: "/tmp".to_string(),
            index_fingerprint: "0".repeat(64),
            hash_algorithm: "sha1".to_string(),
            entries: vec![],
        }),
        "GuardCommitBlob" => Some(Request::GuardCommitBlob {
            transaction_id: 1,
            blob_oid: "0".repeat(40),
            object_size: 0,
            payload: vec![],
        }),
        "GuardCommitFinish" => Some(Request::GuardCommitFinish {
            transaction_id: 1,
            client_objects_streamed: 0,
            client_bytes_streamed: 0,
        }),
        "GuardAdd" => Some(Request::GuardAdd {
            root: "/tmp".to_string(),
            mode: "audit".to_string(),
        }),
        "GuardRemove" => Some(Request::GuardRemove {
            root: "/tmp".to_string(),
        }),
        "GuardStatus" => Some(Request::GuardStatus {
            root: "/tmp".to_string(),
        }),
        "GuardReconcile" => Some(Request::GuardReconcile {
            root: "/tmp".to_string(),
        }),
        "GuardList" => Some(Request::GuardList),
        "GuardFeed" => Some(Request::GuardFeed {
            root: None,
            limit: Some(50),
        }),
        _ => None,
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
        Response::MassReady => "MassReady",
        Response::MassFilesystemReady => "MassFilesystemReady",
        Response::MassFilesystemComplete { .. } => "MassFilesystemComplete",
        Response::MassFilesystemIncrementalError { .. } => "MassFilesystemIncrementalError",
        Response::MassComplete { .. } => "MassComplete",
        Response::Shutdown => "Shutdown",
        Response::Error { .. } => "Error",
        Response::GuardCommitPlan { .. } => "GuardCommitPlan",
        Response::GuardCommitBlobAck { .. } => "GuardCommitBlobAck",
        Response::GuardCommitReceipt { .. } => "GuardCommitReceipt",
        Response::GuardAdded { .. } => "GuardAdded",
        Response::GuardRemoved => "GuardRemoved",
        Response::GuardStatusResult { .. } => "GuardStatusResult",
        Response::GuardReconcileStarted { .. } => "GuardReconcileStarted",
        Response::GuardListResult { .. } => "GuardListResult",
        Response::GuardFeedResult { .. } => "GuardFeedResult",
    }
}

#[cfg(test)]
mod tests;
