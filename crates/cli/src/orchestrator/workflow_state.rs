//! Workflow-state modeling for the operator profile.
//!
//! Every record here is derived from the exact load/lookup evidence captured
//! during the run (Merkle load status, autoroute cache presence, verifier
//! cache-hit spans, per-source input counters, daemon request ids). Nothing
//! is inferred from wall-clock timing, and storage is bounded with explicit
//! loss accounting.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// Explicit cache-state transition observed for one cache layer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CacheTransition {
    /// No usable persisted state existed at load time; the layer rebuilt.
    ColdStart,
    /// Persisted state loaded and served at least part of the run.
    WarmLoad,
    /// Persisted state loaded and served the entire run (zero rescans).
    SteadyState,
    /// The layer is not configured for this run.
    Disabled,
}

impl CacheTransition {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ColdStart => "cold-start",
            Self::WarmLoad => "warm-load",
            Self::SteadyState => "steady-state",
            Self::Disabled => "disabled",
        }
    }
}

/// One layer's transition plus the exact load evidence it was derived from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CacheTransitionRecord {
    pub(crate) layer: keyhog_profile::CacheLayerKindV2,
    pub(crate) evidence: &'static str,
    pub(crate) transition: CacheTransition,
}

fn record(
    layer: keyhog_profile::CacheLayerKindV2,
    evidence: &'static str,
    transition: CacheTransition,
) -> CacheTransitionRecord {
    CacheTransitionRecord {
        layer,
        evidence,
        transition,
    }
}

/// The detector plan is compiled inside this process on every run; there is
/// no persisted detector cache to load, so every run cold-starts this layer.
pub(crate) fn detector_transition() -> CacheTransitionRecord {
    record(
        keyhog_profile::CacheLayerKindV2::Detector,
        "detector-plan-compiled-in-process",
        CacheTransition::ColdStart,
    )
}

/// Hyperscan / Vectorscan shard cache transition.
pub(crate) fn hyperscan_shard_transition(
    cache_path: Option<&std::path::Path>,
    hits: u64,
    misses: u64,
) -> CacheTransitionRecord {
    let (evidence, transition) = if cache_path.is_none() {
        ("hyperscan-shard-cache-disabled", CacheTransition::Disabled)
    } else if hits > 0 {
        ("hyperscan-shard-cache-hits", CacheTransition::WarmLoad)
    } else if misses > 0 {
        ("hyperscan-shards-compiled", CacheTransition::ColdStart)
    } else {
        ("hyperscan-shard-cache-ready", CacheTransition::SteadyState)
    };
    record(
        keyhog_profile::CacheLayerKindV2::HyperscanShards,
        evidence,
        transition,
    )
}

/// MatcherArtifact on-disk cache transition.
pub(crate) fn matcher_artifact_transition(
    outcome: Option<&keyhog_scanner::MatcherArtifactCacheOutcome>,
) -> CacheTransitionRecord {
    let (evidence, transition) = match outcome {
        None | Some(keyhog_scanner::MatcherArtifactCacheOutcome::Disabled) => {
            ("matcher-artifact-disabled", CacheTransition::Disabled)
        }
        Some(keyhog_scanner::MatcherArtifactCacheOutcome::Hit) => {
            ("matcher-artifact-hit", CacheTransition::WarmLoad)
        }
        Some(keyhog_scanner::MatcherArtifactCacheOutcome::Miss) => {
            ("matcher-artifact-miss", CacheTransition::ColdStart)
        }
        Some(keyhog_scanner::MatcherArtifactCacheOutcome::Invalidated { .. }) => {
            ("matcher-artifact-invalidated", CacheTransition::ColdStart)
        }
    };
    record(
        keyhog_profile::CacheLayerKindV2::MatcherArtifacts,
        evidence,
        transition,
    )
}

/// GPU program disk cache transition.
pub(crate) fn gpu_program_transition(hits: u64, misses: u64) -> CacheTransitionRecord {
    let (evidence, transition) = if hits > 0 {
        ("gpu-program-hit", CacheTransition::WarmLoad)
    } else if misses > 0 {
        ("gpu-program-compiled", CacheTransition::ColdStart)
    } else {
        ("gpu-program-idle", CacheTransition::Disabled)
    };
    record(
        keyhog_profile::CacheLayerKindV2::GpuPrograms,
        evidence,
        transition,
    )
}

/// Inter-process lock file transition.
pub(crate) fn lock_file_transition() -> CacheTransitionRecord {
    record(
        keyhog_profile::CacheLayerKindV2::LockFiles,
        "lock-files-active",
        CacheTransition::SteadyState,
    )
}

/// Classify the Merkle incremental-cache load exactly as reported by the
/// loader. A failed load has full evidence (path plus failure kind) and the
/// run rebuilds the cache, so it is a cold start, never `unknown`.
pub(crate) fn merkle_load_transition(
    status: Option<&keyhog_core::MerkleLoadStatus>,
) -> CacheTransitionRecord {
    use keyhog_core::MerkleLoadStatus;
    let (evidence, transition) = match status {
        None => ("merkle-not-configured", CacheTransition::Disabled),
        Some(MerkleLoadStatus::Missing { .. }) => {
            ("merkle-load-missing", CacheTransition::ColdStart)
        }
        Some(MerkleLoadStatus::Loaded { .. }) => ("merkle-load-ok", CacheTransition::WarmLoad),
        Some(MerkleLoadStatus::ReadFailed { .. }) => {
            ("merkle-load-read-failed", CacheTransition::ColdStart)
        }
        Some(MerkleLoadStatus::ParseFailed { .. }) => {
            ("merkle-load-parse-failed", CacheTransition::ColdStart)
        }
        Some(MerkleLoadStatus::SchemaMismatch { .. }) => {
            ("merkle-load-schema-mismatch", CacheTransition::ColdStart)
        }
        Some(MerkleLoadStatus::SpecChanged { .. }) => {
            ("merkle-load-spec-changed", CacheTransition::ColdStart)
        }
        Some(MerkleLoadStatus::InvalidEntryHash { .. }) => {
            ("merkle-load-invalid-entry-hash", CacheTransition::ColdStart)
        }
    };
    record(
        keyhog_profile::CacheLayerKindV2::Merkle,
        evidence,
        transition,
    )
}

/// A warm Merkle load is a steady-state repeat only when the loaded
/// generation served the whole run: at least one unchanged skip and zero
/// chunks dispatched to a backend. Any rescanned chunk keeps it a warm load.
pub(crate) fn refine_merkle_warmth(
    transition: CacheTransition,
    skipped_unchanged: u64,
    scanned_chunks: u64,
) -> CacheTransition {
    if transition == CacheTransition::WarmLoad && skipped_unchanged > 0 && scanned_chunks == 0 {
        CacheTransition::SteadyState
    } else {
        transition
    }
}

/// Autoroute decision state comes from the persisted decision cache path.
pub(crate) fn autoroute_transition(cache_path: Option<&std::path::Path>) -> CacheTransitionRecord {
    let (evidence, transition) = match cache_path {
        None => ("autoroute-cache-not-configured", CacheTransition::Disabled),
        Some(path) if path.exists() => (
            "autoroute-decision-cache-present",
            CacheTransition::WarmLoad,
        ),
        Some(_) => (
            "autoroute-decision-cache-absent",
            CacheTransition::ColdStart,
        ),
    };
    record(
        keyhog_profile::CacheLayerKindV2::Autoroute,
        evidence,
        transition,
    )
}

/// The verifier cache is in-memory and starts empty in every one-shot
/// process; only recorded cache-hit spans can warm it.
pub(crate) fn verifier_transition(enabled: bool, cache_hits: u64) -> CacheTransitionRecord {
    let (evidence, transition) = if !enabled {
        ("verifier-policy-disabled", CacheTransition::Disabled)
    } else if cache_hits > 0 {
        ("verifier-cache-hit-spans", CacheTransition::WarmLoad)
    } else {
        (
            "verifier-cache-empty-at-process-start",
            CacheTransition::ColdStart,
        )
    };
    record(
        keyhog_profile::CacheLayerKindV2::Verifier,
        evidence,
        transition,
    )
}

/// The in-process orchestrator only runs when the daemon route is off;
/// daemon-routed scans surface daemon-served request profiles instead.
pub(crate) fn daemon_transition() -> CacheTransitionRecord {
    record(
        keyhog_profile::CacheLayerKindV2::Daemon,
        "daemon-route-off-in-process",
        CacheTransition::Disabled,
    )
}

/// One measured source partition: the exact input units and bytes one source
/// contributed between its acquisition boundary and the merge seam.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SourcePartitionRecord {
    pub(crate) index: u64,
    pub(crate) kind: String,
    pub(crate) units: u64,
    pub(crate) bytes: u64,
}

/// Partition records are operator evidence, not a hot-path structure: one
/// record per source, and scans name far fewer sources than this cap.
pub(crate) const MAX_RECORDED_PARTITIONS: usize = 1024;

#[derive(Default)]
struct PartitionSink {
    records: Vec<SourcePartitionRecord>,
    dropped: u64,
}

static SOURCE_PARTITIONS: Mutex<PartitionSink> = Mutex::new(PartitionSink {
    records: Vec::new(),
    dropped: 0,
});
static MERKLE_SKIPPED_UNCHANGED: AtomicU64 = AtomicU64::new(0);

/// Clear per-run workflow state. Called once at the start of `run()`.
pub(crate) fn reset_workflow_state() {
    // LAW10: the partition sink is per-run profile evidence, not a finding or coverage
    // path. Recovering a poisoned lock in place keeps the evidence flowing; failing
    // closed here would abort a scan over a telemetry mutex.
    let mut sink = SOURCE_PARTITIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned profile-evidence lock recovery preserves accumulated scan evidence and cannot suppress findings.
    sink.records.clear();
    sink.dropped = 0;
    MERKLE_SKIPPED_UNCHANGED.store(0, Ordering::Relaxed);
}

/// Record one source's measured contribution at its production boundary.
/// Over-cap records are counted, never silently dropped.
pub(crate) fn record_source_partition(kind: &str, units: u64, bytes: u64) {
    // LAW10: profile-evidence sink; see `reset_workflow_state`. Poison recovery keeps
    // partition records surfaced and never affects findings or coverage gaps.
    let mut sink = SOURCE_PARTITIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned profile-evidence lock recovery preserves partition accounting and cannot suppress findings.
    if sink.records.len() >= MAX_RECORDED_PARTITIONS {
        sink.dropped = sink.dropped.saturating_add(1);
        return;
    }
    let index = u64::try_from(sink.records.len()).unwrap_or(u64::MAX); // LAW10: profile partition index saturates only beyond u64 records; scan coverage and findings are unchanged.
    sink.records.push(SourcePartitionRecord {
        index,
        kind: kind.to_owned(),
        units,
        bytes,
    });
}

/// Drain the partition records and the over-cap drop count for the profile.
pub(crate) fn take_source_partitions() -> (Vec<SourcePartitionRecord>, u64) {
    // LAW10: profile-evidence sink; see `reset_workflow_state`. Over-cap drops are
    // counted in `dropped` and drained here, so the cap is never a silent loss.
    let mut sink = SOURCE_PARTITIONS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned profile-evidence lock recovery returns all retained records and the explicit dropped count.
    (
        std::mem::take(&mut sink.records),
        std::mem::take(&mut sink.dropped),
    )
}

/// Accumulate unchanged-skip evidence from the incremental finalize seam.
pub(crate) fn record_merkle_skipped_unchanged(skipped: usize) {
    MERKLE_SKIPPED_UNCHANGED.fetch_add(skipped as u64, Ordering::Relaxed);
}

/// Read the run's unchanged-skip total (non-destructive; reset per run).
pub(crate) fn merkle_skipped_unchanged() -> u64 {
    MERKLE_SKIPPED_UNCHANGED.load(Ordering::Relaxed)
}

/// Per-run verification aggregate: policy state plus exact outcome counts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct VerificationAggregate {
    pub(crate) enabled: bool,
    pub(crate) queued: u64,
    pub(crate) network: u64,
    pub(crate) cached: u64,
    pub(crate) unverifiable: u64,
    pub(crate) skipped: u64,
}

impl VerificationAggregate {
    /// Aggregate state label: `disabled` when the policy is off, `idle` when
    /// nothing qualified for verification, then the dominant serving path.
    pub(crate) fn state_label(&self) -> &'static str {
        if !self.enabled {
            "disabled"
        } else if self.queued == 0 {
            "idle"
        } else if self.cached > 0 && self.network == 0 {
            "cached"
        } else if self.network > 0 && self.cached == 0 {
            "network"
        } else if self.network > 0 && self.cached > 0 {
            "mixed"
        } else {
            "queued"
        }
    }
}

/// Tally the verification outcomes the run actually produced. A finding is
/// `queued` when it entered the verification engine (only low-confidence or
/// policy-skipped findings stay `Skipped`); `network` covers every result
/// that required a provider exchange, including transport errors.
pub(crate) fn aggregate_verification_findings(
    enabled: bool,
    findings: &[keyhog_core::VerifiedFinding],
) -> VerificationAggregate {
    aggregate_verification_results(
        enabled,
        findings.iter().map(|finding| &finding.verification),
    )
}

pub(crate) fn aggregate_verification_results<'a>(
    enabled: bool,
    results: impl ExactSizeIterator<Item = &'a keyhog_core::VerificationResult>,
) -> VerificationAggregate {
    let mut aggregate = VerificationAggregate {
        enabled,
        ..VerificationAggregate::default()
    };
    if !enabled {
        aggregate.skipped = u64::try_from(results.len()).unwrap_or(u64::MAX); // LAW10: disabled verifier accounting saturates only beyond u64 results; findings remain unmodified.
        return aggregate;
    }
    for result in results {
        match result {
            keyhog_core::VerificationResult::Skipped => {
                aggregate.skipped = aggregate.skipped.saturating_add(1);
            }
            keyhog_core::VerificationResult::Unverifiable => {
                aggregate.queued = aggregate.queued.saturating_add(1);
                aggregate.unverifiable = aggregate.unverifiable.saturating_add(1);
            }
            keyhog_core::VerificationResult::Live
            | keyhog_core::VerificationResult::Revoked
            | keyhog_core::VerificationResult::Dead
            | keyhog_core::VerificationResult::RateLimited
            | keyhog_core::VerificationResult::Error(_) => {
                aggregate.queued = aggregate.queued.saturating_add(1);
                aggregate.network = aggregate.network.saturating_add(1);
            }
        }
    }
    aggregate
}

/// Count verifier cache hits in the recorded span forest. A verifier cache
/// hit is an `IncrementalLookup` span recorded inside a `LiveVerification`
/// span (the verifier records one per hit, nothing on a miss); Merkle
/// unchanged-check spans use the same stage but sit under source/dispatch
/// parents, so causal ancestry separates the two.
pub(crate) fn count_verifier_cache_hits(spans: &[keyhog_profile::SpanRecordV2]) -> u64 {
    let parent_of: std::collections::HashMap<u64, (keyhog_profile::MetricId, Option<u64>)> = spans
        .iter()
        .map(|span| {
            let parent = match span.parent_span_id {
                keyhog_profile::Evidence::Recorded { value } => Some(value),
                keyhog_profile::Evidence::Unavailable { .. } => None,
            };
            (span.span_id, (span.metric_id, parent))
        })
        .collect();
    let mut hits = 0_u64;
    for span in spans {
        if span.metric_id != keyhog_profile::MetricId::IncrementalLookup {
            continue;
        }
        let mut cursor = match span.parent_span_id {
            keyhog_profile::Evidence::Recorded { value } => Some(value),
            keyhog_profile::Evidence::Unavailable { .. } => None,
        };
        // Ancestry walk bounded past the runtime's 64-deep nesting cap so a
        // malformed parent chain can never loop forever.
        for _ in 0..65 {
            let Some(id) = cursor else { break };
            let Some((metric, parent)) = parent_of.get(&id) else {
                break;
            };
            if *metric == keyhog_profile::MetricId::LiveVerification {
                hits = hits.saturating_add(1);
                break;
            }
            cursor = *parent;
        }
    }
    hits
}

/// Daemon identity parsed out of one server-assigned request id. The id is
/// `{daemon_generation}-{sequence:016x}`; the generation itself may contain
/// dashes, so the split is on the LAST separator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonRequestIdentity {
    pub(crate) generation: String,
    pub(crate) sequence: u64,
}

pub(crate) fn parse_daemon_request_identity(request_id: &str) -> Option<DaemonRequestIdentity> {
    let (generation, sequence) = request_id.rsplit_once('-')?;
    if generation.is_empty() || sequence.len() != 16 {
        return None;
    }
    let sequence = u64::from_str_radix(sequence, 16).ok()?; // LAW10: malformed optional daemon identity is rejected as absent; it cannot authorize routing or suppress scan work.
    Some(DaemonRequestIdentity {
        generation: generation.to_owned(),
        sequence,
    })
}
