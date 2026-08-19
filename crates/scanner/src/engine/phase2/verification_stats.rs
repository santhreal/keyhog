//! Phase-2 verification and candidate confirmation metrics.
//!
//! Captures fine-grained attribution for phase-2 shared-anchor candidate collection,
//! anchored regex candidate verification, and whole-chunk pattern fallback.

use keyhog_profile::{CounterId, TypedMetricRecordV2};

/// Snapshot of phase-2 verification metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Phase2VerificationProfile {
    /// Nanoseconds spent in candidate collection.
    pub anchor_collect_ns: u64,
    /// Number of candidate collection calls.
    pub anchor_collect_calls: u64,
    /// Total candidate positions collected.
    pub anchor_candidates: u64,
    /// Number of candidate positions verified via anchored regex.
    pub anchored_verify_candidates: u64,
    /// Number of matches emitted by anchored regex verification.
    pub anchored_verify_matches: u64,
    /// Number of whole-chunk pattern scans executed.
    pub whole_chunk_patterns: u64,
    /// Number of matches emitted by whole-chunk pattern scans.
    pub whole_chunk_matches: u64,
}

impl Phase2VerificationProfile {
    /// True when any phase-2 verification activity was recorded.
    pub fn any_recorded(&self) -> bool {
        *self != Self::default()
    }
}

/// Build the phase-2 verification snapshot from drained typed metrics.
pub fn phase2_verification_profile_from_typed(
    metrics: &[TypedMetricRecordV2],
) -> Phase2VerificationProfile {
    let value = |counter: CounterId| {
        metrics
            .iter()
            .find(|record| record.metric_id == counter.metric_id())
            .map_or(0, |record| record.value)
    };
    Phase2VerificationProfile {
        anchor_collect_ns: value(CounterId::Phase2AnchorCollectNs),
        anchor_collect_calls: value(CounterId::Phase2AnchorCollectCalls),
        anchor_candidates: value(CounterId::Phase2AlwaysAnchorCandidateCount),
        anchored_verify_candidates: value(CounterId::Phase2AnchoredVerifyCandidates),
        anchored_verify_matches: value(CounterId::Phase2AnchoredVerifyMatches),
        whole_chunk_patterns: value(CounterId::Phase2WholeChunkPatterns),
        whole_chunk_matches: value(CounterId::Phase2WholeChunkMatches),
    }
}

/// Render the phase-2 verification profile line for the unified profiler.
pub fn format_phase2_verification_profile(p: &Phase2VerificationProfile) -> String {
    let ac_ms = p.anchor_collect_ns as f64 / 1e6;
    format!(
        "=== PHASE2 verification profile === anchor-collect={ac_ms:.1}ms (calls={} cands={}) \
         anchored-verify=(cands={} matches={}) whole-chunk=(patterns={} matches={})",
        p.anchor_collect_calls,
        p.anchor_candidates,
        p.anchored_verify_candidates,
        p.anchored_verify_matches,
        p.whole_chunk_patterns,
        p.whole_chunk_matches,
    )
}
