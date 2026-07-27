//! Allocation-free dispatch plans for the phase-2 always-active prefilter.

use super::gating::PortableGateEvidence;
use super::trigger_evidence::ChunkTriggerEvidence;
use super::{homoglyph_skip_applies, PortablePrefilter, PrefilterBatch};
use crate::scanner_config::ResolvedRuntimeTuningConfig;

/// The pattern ownership slice served by one prefilter invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrefilterScope {
    Full,
    AnchorResidual,
    LocalizedResidual,
}

/// Scalar runtime inputs used to derive a plan. Keeping these independent of
/// matcher state makes planning deterministic and allocation-free.
#[derive(Clone, Copy, Debug)]
pub(super) struct DispatchConfig {
    #[cfg(feature = "simd")]
    pub(super) fallback_hs: bool,
    #[cfg(feature = "simd")]
    pub(super) hs_prefilter_max_len: usize,
    pub(super) homoglyph_gate: bool,
    pub(super) homoglyph_ascii_skip: bool,
    pub(super) fallback_prefix_gate: bool,
    pub(super) prefilter_truncate: bool,
}
impl DispatchConfig {
    #[inline]
    pub(super) fn from_tuning(tuning: &ResolvedRuntimeTuningConfig) -> Self {
        Self {
            #[cfg(feature = "simd")]
            fallback_hs: tuning.fallback_hs,
            #[cfg(feature = "simd")]
            hs_prefilter_max_len: tuning.hs_prefilter_max_len,
            homoglyph_gate: tuning.homoglyph_gate,
            homoglyph_ascii_skip: tuning.homoglyph_ascii_skip,
            fallback_prefix_gate: tuning.fallback_prefix_gate,
            prefilter_truncate: tuning.prefilter_truncate,
        }
    }
}

/// One immutable plan shared by the combined gate, SIMD attempt, and portable
/// fallback. It contains only scalar facts; input size cannot grow the plan.
#[derive(Clone, Copy, Debug)]
pub(super) struct DispatchPlan<'a> {
    chunk: ChunkTriggerEvidence<'a>,
    scope: PrefilterScope,
    #[cfg(feature = "simd")]
    try_hyperscan: bool,
    use_ascii_matcher: bool,
    skip_homoglyph: bool,
    prefix_gate: bool,
    truncate: bool,
}

impl<'a> DispatchPlan<'a> {
    #[inline]
    pub(super) fn for_mark(
        text: &'a str,
        anchor_mode: bool,
        localize_plain: bool,
        allow_hyperscan: bool,
        config: DispatchConfig,
    ) -> Self {
        let chunk = ChunkTriggerEvidence::inspect(text);
        let scope = if !anchor_mode {
            PrefilterScope::Full
        } else if localize_plain && config.homoglyph_gate && chunk.is_ascii() {
            PrefilterScope::LocalizedResidual
        } else {
            PrefilterScope::AnchorResidual
        };
        Self::new(chunk, scope, allow_hyperscan, config)
    }

    #[inline]
    pub(super) fn for_admission(
        text: &'a str,
        allow_hyperscan: bool,
        config: DispatchConfig,
    ) -> Self {
        Self::new(
            ChunkTriggerEvidence::inspect(text),
            PrefilterScope::Full,
            allow_hyperscan,
            config,
        )
    }

    #[inline]
    fn new(
        chunk: ChunkTriggerEvidence<'a>,
        scope: PrefilterScope,
        #[cfg_attr(not(feature = "simd"), allow(unused_variables))] allow_hyperscan: bool,
        config: DispatchConfig,
    ) -> Self {
        Self {
            chunk,
            scope,
            // One owner for both marking and admission. ASCII is match-equivalent
            // at every size; non-ASCII remains bounded by the configured gate.
            #[cfg(feature = "simd")]
            try_hyperscan: allow_hyperscan
                && config.fallback_hs
                && (chunk.len() <= config.hs_prefilter_max_len || chunk.is_ascii()),
            use_ascii_matcher: config.homoglyph_gate && chunk.is_ascii(),
            skip_homoglyph: homoglyph_skip_applies(chunk.is_ascii(), config.homoglyph_ascii_skip),
            prefix_gate: config.fallback_prefix_gate,
            truncate: config.prefilter_truncate,
        }
    }

    #[inline]
    pub(super) fn chunk(self) -> ChunkTriggerEvidence<'a> {
        self.chunk
    }

    #[inline]
    pub(super) fn scope(self) -> PrefilterScope {
        self.scope
    }

    #[cfg(feature = "simd")]
    #[inline]
    pub(super) fn try_hyperscan(self) -> bool {
        self.try_hyperscan
    }

    #[cfg(feature = "simd")]
    #[inline]
    pub(super) fn skip_homoglyph(self) -> bool {
        self.skip_homoglyph
    }

    #[inline]
    pub(super) fn skip_homoglyph_batch(self, batch: &PrefilterBatch) -> bool {
        batch.homoglyph_skippable && self.skip_homoglyph
    }

    #[inline]
    pub(super) fn portable_gates(self, portable: &PortablePrefilter) -> PortableGateEvidence {
        PortableGateEvidence::observe(
            self.chunk,
            self.prefix_gate,
            self.use_ascii_matcher,
            portable,
        )
    }

    #[inline]
    pub(super) fn run_gateable_batch(
        self,
        batch: &PrefilterBatch,
        gates: PortableGateEvidence,
    ) -> bool {
        !batch.gateable || gates.run_gateable_batch(batch.ascii_set.is_some())
    }

    #[inline]
    pub(super) fn matcher_for<'b>(self, batch: &'b PrefilterBatch) -> &'b regex::RegexSet {
        match (
            self.truncate,
            self.use_ascii_matcher,
            &batch.ascii_set,
            &batch.ascii_set_trunc,
        ) {
            (true, true, Some(_), Some(ascii_trunc)) => ascii_trunc,
            (false, true, Some(ascii), _) => ascii,
            (true, _, _, _) => &batch.set_trunc,
            (false, _, _, _) => &batch.set,
        }
    }
}
