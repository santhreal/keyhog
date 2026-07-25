//! Recall-safe phase-2 gating decisions over exact trigger evidence.

use super::trigger_evidence::{ChunkTriggerEvidence, TriggerEvidence};
use super::{CombinedNoCandidateGate, PortablePrefilter};

/// Whether the expensive engine may be bypassed by the combined no-candidate
/// gate. The bypass still runs the gate's exact non-anchorable matchers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CombinedGateDecision {
    Dispatch,
    NonAnchorableOnly,
}

impl CombinedGateDecision {
    #[inline]
    fn from_trigger(trigger: TriggerEvidence) -> Self {
        match trigger {
            TriggerEvidence::Absent => Self::NonAnchorableOnly,
            TriggerEvidence::Present | TriggerEvidence::Unavailable => Self::Dispatch,
        }
    }
}

/// Evaluate the combined gate once. A disabled gate, a degraded build, or
/// non-ASCII text is `Unavailable` evidence and therefore fails closed to the
/// full dispatch path.
#[inline]
pub(super) fn combined_gate_decision(
    chunk: ChunkTriggerEvidence<'_>,
    enabled: bool,
    gate: Option<&CombinedNoCandidateGate>,
) -> CombinedGateDecision {
    let trigger = if enabled && chunk.is_ascii() {
        match gate {
            Some(gate) if gate.anchor_present(chunk.text()) => TriggerEvidence::Present,
            Some(_) => TriggerEvidence::Absent,
            None => TriggerEvidence::Unavailable,
        }
    } else {
        TriggerEvidence::Unavailable
    };
    CombinedGateDecision::from_trigger(trigger)
}

/// Exact prefix evidence shared by every portable batch. It is computed once
/// per partition, then each batch only selects the relevant boolean.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PortableGateEvidence {
    ci: TriggerEvidence,
    plain: TriggerEvidence,
}

impl PortableGateEvidence {
    #[inline]
    pub(super) fn observe(
        chunk: ChunkTriggerEvidence<'_>,
        enabled: bool,
        use_ascii_plain: bool,
        portable: &PortablePrefilter,
    ) -> Self {
        Self {
            // Unicode case folding is broader than the ASCII-insensitive AC.
            // Therefore CI evidence is unavailable on non-ASCII input.
            ci: if enabled && chunk.is_ascii() {
                chunk.observe_ac(portable.ci_gate.as_ref())
            } else {
                TriggerEvidence::Unavailable
            },
            // Folded plain literals describe only the ASCII alternate matcher.
            plain: if enabled && use_ascii_plain {
                chunk.observe_ac(portable.plain_gate.as_ref())
            } else {
                TriggerEvidence::Unavailable
            },
        }
    }

    #[inline]
    pub(super) fn run_gateable_batch(self, plain: bool) -> bool {
        !matches!(
            if plain { self.plain } else { self.ci },
            TriggerEvidence::Absent
        )
    }

}
