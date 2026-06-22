//! Single candidate-adjudication funnel.
//!
//! Emission paths find candidate values. This module decides whether a candidate
//! is reportable and names the stage that made the decision.

use crate::suppression::NamedDetectorSuppressionCtx;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageId {
    NamedDetectorSuppression,
}

impl StageId {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NamedDetectorSuppression => "named_detector_suppressed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageOutcome {
    Pass,
    Suppress(StageId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    Suppressed(StageId),
    Reported,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CandidateMatch<'a> {
    credential: &'a str,
}

impl<'a> CandidateMatch<'a> {
    pub(crate) const fn new(credential: &'a str) -> Self {
        Self { credential }
    }

    pub(crate) const fn credential(self) -> &'a str {
        self.credential
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MatchCtx<'a> {
    named_detector_suppression: Option<NamedDetectorSuppressionCtx<'a>>,
}

impl<'a> MatchCtx<'a> {
    pub(crate) const fn for_named_detector(ctx: NamedDetectorSuppressionCtx<'a>) -> Self {
        Self {
            named_detector_suppression: Some(ctx),
        }
    }
}

type StageFn = for<'a> fn(CandidateMatch<'a>, &MatchCtx<'a>) -> StageOutcome;

const STAGES: &[StageFn] = &[named_detector_suppression_stage];

pub(crate) fn adjudicate_match(candidate: CandidateMatch<'_>, ctx: &MatchCtx<'_>) -> Verdict {
    for stage in STAGES {
        match stage(candidate, ctx) {
            StageOutcome::Pass => {}
            StageOutcome::Suppress(stage_id) => return Verdict::Suppressed(stage_id),
        }
    }
    Verdict::Reported
}

fn named_detector_suppression_stage(
    candidate: CandidateMatch<'_>,
    ctx: &MatchCtx<'_>,
) -> StageOutcome {
    let Some(suppression_ctx) = ctx.named_detector_suppression else {
        return StageOutcome::Pass;
    };
    if crate::suppression::suppress_named_detector_finding(candidate.credential(), suppression_ctx)
    {
        StageOutcome::Suppress(StageId::NamedDetectorSuppression)
    } else {
        StageOutcome::Pass
    }
}
