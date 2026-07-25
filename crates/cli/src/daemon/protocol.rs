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

pub(crate) const WIRE_VERSION: u32 = 8;

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


/// Maximum length of a single framed message body. 64 MiB ceiling
/// matches `MAX_SCAN_CHUNK_BYTES * 64` so a chunk batch fits, but
/// bounds the recv buffer so a hostile client can't OOM the daemon
/// by lying about the length prefix.
pub(crate) const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

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
pub(crate) enum Response {
    Hello {
        wire_version: u32,
        keyhog_version: String,
        git_hash: String,
        detector_rules_digest: String,
        /// `autoroute`, `autoroute-recovery` for invalid startup evidence,
        /// `autoroute-degraded` for persisted route quarantine, or the canonical
        /// label of a backend forced at daemon startup.
        backend_policy: String,
        detector_count: usize,
        uptime_secs: u64,
        warm_backend: WarmBackendStatus,

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
        /// Exact completed recovery for this request, when a selected route
        /// faulted or autoroute state was invalid. `None` means no recovery.
        backend_recovery: RequiredOption<BackendRecoveryStatus>,
    },
    Health {
        uptime_secs: u64,
        scans_served: u64,
        active_scans: u32,
        detector_count: usize,
        backend_recoveries: u64,
        last_backend_fault: Option<BackendRecoveryStatus>,
        warm_backend: WarmBackendStatus,
    },
    /// Anything that went wrong on the server side. Connection stays
    /// open so the client can retry with a different request.
    Error { message: String },
    /// Acknowledgement for `Shutdown`. The daemon closes the socket
    /// after sending this; the client should not write again.
    Shutdown,
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

    pub(crate) fn is_some(&self) -> bool {
        matches!(self, RequiredOption::Some(_))
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
    }

    pub(crate) fn is_empty(self) -> bool {
        self.total() == 0
    }

    #[cfg(test)]
    pub(crate) fn fail_class_empty(self) -> bool {
        self.fail_class_total() == 0
    }
}

/// Explicit plaintext adapter for the authenticated, user-only daemon socket.
///
/// `RawMatch` intentionally refuses implicit plaintext serialization. This
/// private DTO is the sole IPC boundary that exposes `credential.as_str()`;
/// deserialization moves the temporary owned string directly into
/// `SensitiveString`, whose storage is zeroized on drop.
mod protected_raw_matches {
    use super::{
        CompanionMap, CredentialHash, MatchLocation, RawMatch, SensitiveString, Severity,
    };
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
        credential: &&SensitiveString,
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

    fn serialize_companions<S>(
        companions: &&CompanionMap,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
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
