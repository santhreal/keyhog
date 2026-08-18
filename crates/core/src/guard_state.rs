//! Perpetual guard root state machine, policy identity, and receipt types.
//!
//! This module owns the versioned non-secret guard state types that every
//! other lane builds on. It does not import CLI, transport, or presentation
//! code (one-way dependency: core state is the bottom of the stack).
//!
//! ## State machine
//!
//! Every registered root has exactly one [`GuardRootState`]. Transitions are
//! centralized in [`GuardRootState::transition`] so adding a state makes the
//! state/exit/documentation matrix test fail until a decision is recorded.
//!
//! ## Policy identity
//!
//! [`GuardPolicyIdentity`] binds every input capable of changing findings or
//! coverage. A mismatch makes existing attestations ineligible immediately.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Schema ───────────────────────────────────────────────────────────────

/// Current guard state schema version. Bumped on any incompatible change to
/// the durable store layout or the serialized shapes in this module.
pub const GUARD_SCHEMA_VERSION: u32 = 1;

/// Current finding/report semantics bound into reusable clean attestations.
/// Version 2 adds canonical evidence verdicts and path-conditioned staged roles.
pub const GUARD_REPORT_SEMANTICS_VERSION: u32 = 2;

/// Git object hash algorithm supported by the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitHashAlgorithm {
    /// Git's default object hash.
    Sha1,
    /// Git's SHA-256 object hash (requires `extensions.objectFormat`).
    Sha256,
}

// ── Root mode ────────────────────────────────────────────────────────────

/// Whether a guarded root is a Git repository or a plain filesystem root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardRootMode {
    /// Repository mode: uses Git object IDs for exact staged-content identity.
    Repo,
    /// Filesystem mode: uses content hashes, not immutable Git OIDs.
    Filesystem,
}

impl GuardRootMode {
    /// All variants in declaration order, for exhaustive test derivation.
    pub fn all() -> &'static [GuardRootMode] {
        &[GuardRootMode::Repo, GuardRootMode::Filesystem]
    }

    /// Stable string label for status output and documentation.
    pub fn label(self) -> &'static str {
        match self {
            GuardRootMode::Repo => "repo",
            GuardRootMode::Filesystem => "filesystem",
        }
    }
}

// ── Root state ───────────────────────────────────────────────────────────

/// The explicit state of one registered guard root.
///
/// Adding a variant here MUST be accompanied by:
/// 1. A transition decision in [`GuardRootState::transition`].
/// 2. An exit-code mapping in the CLI exit module.
/// 3. A status/documentation table entry.
///
/// The state-matrix test fails until all three are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardRootState {
    /// Initial reconciliation or requested full repair is running.
    Indexing,
    /// Baseline completed, all accepted events through the receipt sequence
    /// were processed, policy identity matches, and no unresolved finding
    /// exists. Background state alone is still insufficient to authorize a
    /// commit; an exact staged transaction is required.
    Current,
    /// Accepted filesystem events are queued or scanning.
    Dirty,
    /// At least one current file or staged blob produced an unsuppressed
    /// finding.
    Blocked,
    /// Event loss, source gap, unreadable input, queue overflow, root
    /// replacement, mount discontinuity, or persistence failure prevents
    /// complete coverage.
    Degraded,
    /// Binary, detector, suppression, preprocessing, schema, or resolved
    /// configuration identity differs from persisted attestations.
    StalePolicy,
    /// Root is registered but not actively watched.
    Stopped,
}

impl GuardRootState {
    /// Whether this state permits a commit authorization.
    ///
    /// This is always `false` for background states. The exact staged
    /// transaction is the only local commit authorization input.
    pub fn may_authorize_commit(self) -> bool {
        // Even `Current` returns false here: background state alone never
        // authorizes a commit. The hook must always submit the exact staged
        // manifest.
        false
    }

    /// Whether this state indicates the root needs explicit repair action.
    pub fn needs_repair(self) -> bool {
        matches!(self, GuardRootState::Degraded | GuardRootState::StalePolicy)
    }

    /// All variants in declaration order, for exhaustive test derivation.
    pub fn all() -> &'static [GuardRootState] {
        &[
            GuardRootState::Indexing,
            GuardRootState::Current,
            GuardRootState::Dirty,
            GuardRootState::Blocked,
            GuardRootState::Degraded,
            GuardRootState::StalePolicy,
            GuardRootState::Stopped,
        ]
    }

    /// Stable string label for status output and documentation.
    pub fn label(self) -> &'static str {
        match self {
            GuardRootState::Indexing => "indexing",
            GuardRootState::Current => "current",
            GuardRootState::Dirty => "dirty",
            GuardRootState::Blocked => "blocked",
            GuardRootState::Degraded => "degraded",
            GuardRootState::StalePolicy => "stale-policy",
            GuardRootState::Stopped => "stopped",
        }
    }
}

impl std::fmt::Display for GuardRootState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── Transition events ────────────────────────────────────────────────────

/// Events that drive the root state machine.
///
/// Adding a variant here MUST be handled in [`GuardRootState::transition`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardTransition {
    /// Registration or explicit reconciliation started (stopped -> indexing).
    ReconciliationStarted,
    /// Initial reconciliation or repair completed with no findings.
    ReconciliationClean,
    /// Initial reconciliation or repair completed with unsuppressed findings.
    ReconciliationFindings,
    /// Initial reconciliation or repair completed but coverage is incomplete.
    ReconciliationDegraded,
    /// A filesystem event was accepted while current or blocked.
    EventAccepted,
    /// All queued events through the current sequence were processed with no
    /// findings.
    EventsClean,
    /// All queued events were processed and at least one has a finding.
    EventsFindings,
    /// All queued events were processed but coverage is incomplete.
    EventsDegraded,
    /// Watcher overflow, queue overflow, unreadable input, lost root,
    /// persistence failure, or journal discontinuity.
    CoverageLost,
    /// Binary, detector, suppression, preprocessing, schema, or config
    /// identity changed.
    PolicyChanged,
    /// Explicit or automatic full reconciliation announced (from degraded or
    /// stale-policy back to indexing).
    RepairStarted,
    /// Root removed from active watching.
    Stopped,
}

/// Error returned when a transition is not legal from the current state.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransitionError {
    /// The transition event is not legal from the current state.
    #[error("illegal guard transition: {event} from state {from}. Fix: run `keyhog guard status <root>` or reconcile the root before dispatching events")]
    Illegal {
        /// The event that was rejected.
        event: GuardTransition,
        /// The state the root was in.
        from: GuardRootState,
    },
}

impl GuardTransition {
    /// All transition variants in declaration order.
    pub fn all() -> &'static [GuardTransition] {
        &[
            GuardTransition::ReconciliationStarted,
            GuardTransition::ReconciliationClean,
            GuardTransition::ReconciliationFindings,
            GuardTransition::ReconciliationDegraded,
            GuardTransition::EventAccepted,
            GuardTransition::EventsClean,
            GuardTransition::EventsFindings,
            GuardTransition::EventsDegraded,
            GuardTransition::CoverageLost,
            GuardTransition::PolicyChanged,
            GuardTransition::RepairStarted,
            GuardTransition::Stopped,
        ]
    }
    /// Human-readable kebab-case label for this transition.
    pub fn label(&self) -> &'static str {
        match self {
            GuardTransition::ReconciliationStarted => "reconciliation-started",
            GuardTransition::ReconciliationClean => "reconciliation-clean",
            GuardTransition::ReconciliationFindings => "reconciliation-findings",
            GuardTransition::ReconciliationDegraded => "reconciliation-degraded",
            GuardTransition::EventAccepted => "event-accepted",
            GuardTransition::EventsClean => "events-clean",
            GuardTransition::EventsFindings => "events-findings",
            GuardTransition::EventsDegraded => "events-degraded",
            GuardTransition::CoverageLost => "coverage-lost",
            GuardTransition::PolicyChanged => "policy-changed",
            GuardTransition::RepairStarted => "repair-started",
            GuardTransition::Stopped => "stopped",
        }
    }
}

impl std::fmt::Display for GuardTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

impl GuardRootState {
    /// Apply one transition event, returning the new state or an error.
    ///
    /// This is the SINGLE owner of the transition function. Every legal
    /// transition is enumerated here; anything not listed is rejected. Adding
    /// a state or event without updating this function and its tests is a
    /// compile-time or test-time failure.
    pub fn transition(self, event: &GuardTransition) -> Result<GuardRootState, TransitionError> {
        use GuardRootState as S;
        use GuardTransition as T;

        let result = match (self, event) {
            // stopped -> indexing
            (S::Stopped, T::ReconciliationStarted) => Some(S::Indexing),
            // indexing -> current | blocked | degraded
            (S::Indexing, T::ReconciliationClean) => Some(S::Current),
            (S::Indexing, T::ReconciliationFindings) => Some(S::Blocked),
            (S::Indexing, T::ReconciliationDegraded) => Some(S::Degraded),
            // current | blocked -> dirty
            (S::Current, T::EventAccepted) => Some(S::Dirty),
            (S::Blocked, T::EventAccepted) => Some(S::Dirty),
            // dirty -> current | blocked | degraded
            (S::Dirty, T::EventsClean) => Some(S::Current),
            (S::Dirty, T::EventsFindings) => Some(S::Blocked),
            (S::Dirty, T::EventsDegraded) => Some(S::Degraded),
            // any active state -> degraded on coverage loss
            (S::Indexing, T::CoverageLost) => Some(S::Degraded),
            (S::Current, T::CoverageLost) => Some(S::Degraded),
            (S::Dirty, T::CoverageLost) => Some(S::Degraded),
            (S::Blocked, T::CoverageLost) => Some(S::Degraded),
            // any active state -> stale-policy on identity change
            (S::Indexing, T::PolicyChanged) => Some(S::StalePolicy),
            (S::Current, T::PolicyChanged) => Some(S::StalePolicy),
            (S::Dirty, T::PolicyChanged) => Some(S::StalePolicy),
            (S::Blocked, T::PolicyChanged) => Some(S::StalePolicy),
            // degraded | stale-policy -> indexing only through reconciliation
            (S::Degraded, T::RepairStarted) => Some(S::Indexing),
            (S::StalePolicy, T::RepairStarted) => Some(S::Indexing),
            // any state -> stopped
            (S::Stopped, T::Stopped) => Some(S::Stopped),
            (S::Indexing, T::Stopped) => Some(S::Stopped),
            (S::Current, T::Stopped) => Some(S::Stopped),
            (S::Dirty, T::Stopped) => Some(S::Stopped),
            (S::Blocked, T::Stopped) => Some(S::Stopped),
            (S::Degraded, T::Stopped) => Some(S::Stopped),
            (S::StalePolicy, T::Stopped) => Some(S::Stopped),
            // degraded can also report coverage loss again (stays degraded)
            (S::Degraded, T::CoverageLost) => Some(S::Degraded),
            // stale-policy can report policy change again (stays stale-policy)
            (S::StalePolicy, T::PolicyChanged) => Some(S::StalePolicy),
            // everything else is illegal
            _ => None,
        };

        result.ok_or(TransitionError::Illegal {
            event: event.clone(),
            from: self,
        })
    }
}

// ── Policy identity ──────────────────────────────────────────────────────

/// Every input capable of changing findings or coverage, bound into one
/// canonical identity. A mismatch makes existing attestations ineligible
/// immediately and transitions the root to [`GuardRootState::StalePolicy`].
///
/// Adding a new behavior-affecting setting MUST add a field here or explicitly
/// classify it as presentation-only. The identity coverage test fails until
/// the field is added.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GuardPolicyIdentity {
    /// Git commit SHA the binary was built from, or `"unknown"`.
    pub build_identity: String,
    /// Effective detector corpus digest (BLAKE3, hex).
    pub detector_digest: String,
    /// Suppression file digest (BLAKE3, hex), or empty if no suppressions.
    pub suppression_digest: String,
    /// `.keyhogignore.toml` rule-filter digest (BLAKE3, hex), or empty.
    pub keyhogignore_digest: String,
    /// Resolved CLI/TOML/default scan configuration digest (BLAKE3, hex).
    pub config_digest: String,
    /// Decode/preprocessing policy version.
    pub decode_policy_version: u32,
    /// Maximum file size and source exclusion policy digest (BLAKE3, hex).
    pub source_policy_digest: String,
    /// Guard state schema version ([`GUARD_SCHEMA_VERSION`]).
    pub guard_schema_version: u32,
    /// Report semantics version where it affects reusable clean status.
    pub report_semantics_version: u32,
}

impl GuardPolicyIdentity {
    /// Short hex digest of the full identity for status display (first 12
    /// hex chars of a BLAKE3 hash over the canonical serialization).
    pub fn short_digest(&self) -> Result<String, serde_json::Error> {
        let bytes = serde_json::to_vec(self)?;
        let hash = blake3::hash(&bytes);
        Ok(hex::encode(&hash.as_bytes()[..6]))
    }

    /// Whether two identities are compatible for attestation reuse.
    pub fn is_compatible_with(&self, other: &GuardPolicyIdentity) -> bool {
        self == other
    }
}

// ── Clean attestation ────────────────────────────────────────────────────

/// Summary of a complete clean scan outcome for one Git blob, suitable for
/// durable reuse. Only complete clean outcomes are reusable: a blob that
/// produced a finding, coverage gap, panic, persistence failure, or
/// incomplete report is never inserted as clean.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GitCleanAttestation {
    /// Git object hash algorithm.
    pub hash_algorithm: GitHashAlgorithm,
    /// Staged blob object ID (hex).
    pub blob_oid: String,
    /// Exact object size in bytes.
    pub object_size: u64,
    /// Policy identity that produced the clean outcome.
    pub policy_identity: GuardPolicyIdentity,
    /// Monotonically increasing event sequence when the attestation was
    /// recorded.
    pub last_seen_sequence: u64,
}

/// Key for the clean attestation lookup: hash algorithm + blob OID + policy
/// identity. Backend identity is recorded in the receipt but does not create
/// different correctness outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GitCleanAttestationKey<'a> {
    /// Git object hash algorithm.
    pub hash_algorithm: GitHashAlgorithm,
    /// Staged blob object ID (hex).
    pub blob_oid: &'a str,
    /// Policy identity digest (short hex).
    pub policy_short_digest: &'a str,
}

// ── Receipt ──────────────────────────────────────────────────────────────

/// Terminal receipt for a guard commit transaction or background
/// reconciliation. Carries exact byte and object totals so the client can
/// validate conservation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardReceipt {
    /// Number of objects requested in the transaction.
    pub objects_requested: u64,
    /// Number of objects served from the clean attestation cache (no payload
    /// read).
    pub objects_hit: u64,
    /// Number of objects scanned.
    pub objects_scanned: u64,
    /// Number of objects skipped (deletions, symlinks, submodules).
    pub objects_skipped: u64,
    /// Total bytes requested.
    pub bytes_requested: u64,
    /// Total bytes served from cache.
    pub bytes_hit: u64,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Number of unsuppressed findings (without secret values).
    pub findings_count: u64,
    /// Number of coverage gaps.
    pub coverage_gaps: u64,
    /// Terminal root state after the transaction.
    pub terminal_state: GuardRootState,
    /// Policy identity under which the receipt was produced.
    pub policy_identity: GuardPolicyIdentity,
    /// Monotonically increasing event sequence at completion.
    pub terminal_sequence: u64,
}

impl GuardReceipt {
    /// Validate conservation of object count and bytes.
    ///
    /// `objects_requested == objects_hit + objects_scanned + objects_skipped`
    /// and `bytes_requested == bytes_hit + bytes_scanned` (skipped objects
    /// contribute zero bytes).
    pub fn validate_conservation(&self) -> Result<(), ReceiptError> {
        let obj_sum = self.objects_hit + self.objects_scanned + self.objects_skipped;
        if obj_sum != self.objects_requested {
            return Err(ReceiptError::ObjectMismatch {
                requested: self.objects_requested,
                accounted: obj_sum,
            });
        }
        let byte_sum = self.bytes_hit + self.bytes_scanned;
        if byte_sum != self.bytes_requested {
            return Err(ReceiptError::ByteMismatch {
                requested: self.bytes_requested,
                accounted: byte_sum,
            });
        }
        Ok(())
    }
}

/// Error returned when receipt conservation validation fails.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReceiptError {
    /// Object count does not conserve.
    #[error("receipt object mismatch: requested {requested}, accounted {accounted}. Fix: ensure all transaction items are accounted for before finalizing the guard receipt")]
    ObjectMismatch {
        /// Objects requested in the transaction.
        requested: u64,
        /// Hit + scanned + skipped.
        accounted: u64,
    },
    /// Byte count does not conserve.
    #[error("receipt byte mismatch: requested {requested}, accounted {accounted}. Fix: ensure all byte ranges are accounted for before finalizing the guard receipt")]
    ByteMismatch {
        /// Bytes requested in the transaction.
        requested: u64,
        /// Hit + scanned.
        accounted: u64,
    },
}

// ── Root registration ────────────────────────────────────────────────────

/// Persistent record for one registered guard root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardRootRecord {
    /// Canonical root path (bytes, no lossy Unicode conversion).
    pub canonical_path: Vec<u8>,
    /// Filesystem identity (device + inode on Unix, volume serial on Windows).
    pub filesystem_identity: FilesystemIdentity,
    /// Repository or filesystem mode.
    pub mode: GuardRootMode,
    /// Current root state.
    pub state: GuardRootState,
    /// Terminal event sequence.
    pub terminal_sequence: u64,
    /// Accepted event sequence (events received from the watcher).
    pub accepted_event_sequence: u64,
    /// Completed event sequence (events fully processed).
    pub completed_event_sequence: u64,
    /// Unix timestamp (seconds) of the initial reconciliation completion.
    pub initial_reconciliation_time: Option<u64>,
    /// Unix timestamp (seconds) of the last reconciliation completion.
    pub last_reconciliation_time: Option<u64>,
    /// Backend route label used for the last scan.
    pub backend_route_label: String,
    /// Last complete receipt summary (non-secret).
    pub last_receipt: Option<GuardReceipt>,
}

/// Non-secret filesystem identity for root replacement detection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FilesystemIdentity {
    /// Device ID (Unix `st_dev` or Windows volume serial).
    pub device: u64,
    /// Inode number (Unix `st_ino` or Windows file index).
    pub inode: u64,
}
