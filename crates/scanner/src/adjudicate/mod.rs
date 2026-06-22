//! Single candidate-adjudication funnel.
//!
//! Emission paths find candidate values. This module decides whether a candidate
//! is reportable and names the stage that made the decision.

use crate::suppression::NamedDetectorSuppressionCtx;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StageId {
    AwsAccessKeyLengthInvalid,
    AnthropicLegacyLengthInvalid,
    WithinHexContext,
    HexDigestFragment,
    ProbabilisticGateNotPromising,
    FalsePositiveContext,
    MissingRequiredCompanion,
    EntropyBelowFloor,
    CamelCaseNoDigit,
    ChecksumInvalid,
    ScoringRejected,
    ReportConfidenceRejected,
    NamedDetectorSuppression,
}

impl StageId {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AwsAccessKeyLengthInvalid => "aws_access_key_length_invalid",
            Self::AnthropicLegacyLengthInvalid => "anthropic_legacy_length_invalid",
            Self::WithinHexContext => "within_hex_context",
            Self::HexDigestFragment => "hex_digest_fragment",
            Self::ProbabilisticGateNotPromising => "probabilistic_gate_not_promising",
            Self::FalsePositiveContext => "false_positive_context",
            Self::MissingRequiredCompanion => "missing_required_companion",
            Self::EntropyBelowFloor => "entropy_below_floor",
            Self::CamelCaseNoDigit => "camel_case_no_digit",
            Self::ChecksumInvalid => "checksum_invalid",
            Self::ScoringRejected => "scoring_rejected",
            Self::ReportConfidenceRejected => "report_confidence_rejected",
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

impl Verdict {
    pub(crate) const fn suppressed_stage(self) -> Option<StageId> {
        match self {
            Self::Suppressed(stage_id) => Some(stage_id),
            Self::Reported => None,
        }
    }
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
pub(crate) struct ProcessCandidateSignals {
    stage_id: Option<StageId>,
}

impl ProcessCandidateSignals {
    const fn pass() -> Self {
        Self { stage_id: None }
    }

    const fn suppress(stage_id: StageId) -> Self {
        Self {
            stage_id: Some(stage_id),
        }
    }

    pub(crate) fn from_match(
        detector_id: &str,
        credential: &str,
        data: &str,
        credential_start: usize,
        match_end: usize,
    ) -> Self {
        if detector_id == crate::detector_ids::AWS_ACCESS_KEY && credential.len() != 20 {
            return Self::suppress(StageId::AwsAccessKeyLengthInvalid);
        }
        if detector_id == crate::detector_ids::ANTHROPIC_API_KEY
            && credential
                .strip_prefix("sk-ant-api03-")
                .is_some_and(|body| !(80..=120).contains(&body.len()))
        {
            return Self::suppress(StageId::AnthropicLegacyLengthInvalid);
        }
        if crate::pipeline::is_within_hex_context(data, credential_start, match_end) {
            return Self::suppress(StageId::WithinHexContext);
        }
        if is_hex_digest_fragment(data, credential_start, match_end, credential) {
            return Self::suppress(StageId::HexDigestFragment);
        }
        if crate::detector_ids::is_generic_detector(detector_id)
            && crate::confidence::known_prefix_confidence_floor(credential).is_none()
            && !crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential)
        {
            return Self::suppress(StageId::ProbabilisticGateNotPromising);
        }
        Self::pass()
    }

    pub(crate) const fn from_false_positive_context(false_positive_context: bool) -> Self {
        if false_positive_context {
            Self::suppress(StageId::FalsePositiveContext)
        } else {
            Self::pass()
        }
    }

    pub(crate) const fn from_missing_required_companion(missing_required_companion: bool) -> Self {
        if missing_required_companion {
            Self::suppress(StageId::MissingRequiredCompanion)
        } else {
            Self::pass()
        }
    }

    pub(crate) const fn from_entropy_shape(
        entropy_below_floor: bool,
        camel_case_no_digit: bool,
    ) -> Self {
        if entropy_below_floor {
            Self::suppress(StageId::EntropyBelowFloor)
        } else if camel_case_no_digit {
            Self::suppress(StageId::CamelCaseNoDigit)
        } else {
            Self::pass()
        }
    }

    pub(crate) const fn from_checksum_invalid(checksum_invalid: bool) -> Self {
        if checksum_invalid {
            Self::suppress(StageId::ChecksumInvalid)
        } else {
            Self::pass()
        }
    }

    pub(crate) const fn from_scoring_rejected(scoring_rejected: bool) -> Self {
        if scoring_rejected {
            Self::suppress(StageId::ScoringRejected)
        } else {
            Self::pass()
        }
    }

    pub(crate) const fn from_report_confidence_rejected(report_confidence_rejected: bool) -> Self {
        if report_confidence_rejected {
            Self::suppress(StageId::ReportConfidenceRejected)
        } else {
            Self::pass()
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MatchCtx<'a> {
    process_signals: Option<ProcessCandidateSignals>,
    named_detector_suppression: Option<NamedDetectorSuppressionCtx<'a>>,
}

impl<'a> MatchCtx<'a> {
    pub(crate) const fn for_process_signals(process_signals: ProcessCandidateSignals) -> Self {
        Self {
            process_signals: Some(process_signals),
            named_detector_suppression: None,
        }
    }

    pub(crate) const fn for_named_detector(ctx: NamedDetectorSuppressionCtx<'a>) -> Self {
        Self {
            process_signals: None,
            named_detector_suppression: Some(ctx),
        }
    }
}

type StageFn = for<'candidate, 'ctx, 'borrow> fn(
    CandidateMatch<'candidate>,
    &'borrow MatchCtx<'ctx>,
) -> StageOutcome;

const STAGES: &[StageFn] = &[process_signal_stage, named_detector_suppression_stage];

pub(crate) fn adjudicate_match(candidate: CandidateMatch<'_>, ctx: &MatchCtx<'_>) -> Verdict {
    for stage in STAGES {
        match stage(candidate, ctx) {
            StageOutcome::Pass => {}
            StageOutcome::Suppress(stage_id) => return Verdict::Suppressed(stage_id),
        }
    }
    Verdict::Reported
}

fn process_signal_stage(_candidate: CandidateMatch<'_>, ctx: &MatchCtx<'_>) -> StageOutcome {
    let Some(signals) = ctx.process_signals else {
        return StageOutcome::Pass;
    };
    if let Some(stage_id) = signals.stage_id {
        return StageOutcome::Suppress(stage_id);
    }
    StageOutcome::Pass
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

/// True when `credential` (a pure-hex token at `data[start..end]`) is a slice
/// of a longer contiguous hex run reaching digest length (>=40 chars: SHA-1,
/// git commit SHA, or SHA-256). Genuine fixed-length hex API keys are
/// delimiter-bounded, so no surrounding hex run is present and this returns
/// false.
fn is_hex_digest_fragment(data: &str, start: usize, end: usize, credential: &str) -> bool {
    if credential.len() < 16 || !credential.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let bytes = data.as_bytes();
    if start > end || end > bytes.len() {
        return false;
    }
    let before = bytes[..start]
        .iter()
        .rev()
        .take_while(|b| b.is_ascii_hexdigit())
        .count();
    let after = bytes[end..]
        .iter()
        .take_while(|b| b.is_ascii_hexdigit())
        .count();
    if before == 0 && after == 0 {
        return false;
    }
    before + credential.len() + after >= 40
}
