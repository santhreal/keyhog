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

/// Exact prefix evidence shared by every portable batch. It is computed lazily
/// on first need per partition, avoiding wasted AC scans when batches are skipped.
pub(super) struct PortableGateEvidence<'a> {
    chunk: ChunkTriggerEvidence<'a>,
    enabled: bool,
    use_ascii_plain: bool,
    portable: &'a PortablePrefilter,
    ci: std::cell::Cell<Option<TriggerEvidence>>,
    plain: std::cell::Cell<Option<TriggerEvidence>>,
}

impl<'a> PortableGateEvidence<'a> {
    #[inline]
    pub(super) fn new(
        chunk: ChunkTriggerEvidence<'a>,
        enabled: bool,
        use_ascii_plain: bool,
        portable: &'a PortablePrefilter,
    ) -> Self {
        Self {
            chunk,
            enabled,
            use_ascii_plain,
            portable,
            ci: std::cell::Cell::new(None),
            plain: std::cell::Cell::new(None),
        }
    }

    #[inline]
    pub(super) fn observe(
        chunk: ChunkTriggerEvidence<'a>,
        enabled: bool,
        use_ascii_plain: bool,
        portable: &'a PortablePrefilter,
    ) -> Self {
        Self::new(chunk, enabled, use_ascii_plain, portable)
    }

    #[inline]
    fn ci_evidence(&self) -> TriggerEvidence {
        if let Some(ev) = self.ci.get() {
            return ev;
        }
        let ev = if self.enabled && self.chunk.is_ascii() {
            self.chunk.observe_ac(self.portable.ci_gate.as_ref())
        } else {
            TriggerEvidence::Unavailable
        };
        self.ci.set(Some(ev));
        ev
    }

    #[inline]
    fn plain_evidence(&self) -> TriggerEvidence {
        if let Some(ev) = self.plain.get() {
            return ev;
        }
        let ev = if self.enabled && self.use_ascii_plain {
            self.chunk.observe_ac(self.portable.plain_gate.as_ref())
        } else {
            TriggerEvidence::Unavailable
        };
        self.plain.set(Some(ev));
        ev
    }

    #[inline]
    pub(super) fn run_gateable_batch(&self, plain: bool) -> bool {
        let ev = if plain {
            self.plain_evidence()
        } else {
            self.ci_evidence()
        };
        !matches!(ev, TriggerEvidence::Absent)
    }
}
