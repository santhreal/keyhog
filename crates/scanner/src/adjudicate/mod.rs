//! Single candidate-adjudication funnel.
//!
//! Emission paths find candidate values. This module decides whether a candidate
//! is reportable and names the stage that made the decision.

mod entropy;
mod generic;
mod stage;

use crate::suppression::NamedDetectorSuppressionCtx;
use keyhog_core::RawMatch;

pub(crate) use entropy::{EntropyFallbackSignal, EntropyGenerationSignal, EntropyShapeStage};
pub(crate) use generic::{GenericBridgeSignal, GenericValueShapeStage};
pub(crate) use stage::{StageId, StageOutcome, Verdict};

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HotPatternSignal {
    SuppressionStage(StageId),
    ShapeGate(&'static str),
    ChecksumInvalid,
}

impl HotPatternSignal {
    const fn stage_id(self) -> StageId {
        match self {
            Self::SuppressionStage(stage_id) => stage_id,
            Self::ShapeGate(reason) => StageId::ShapeGate(reason),
            Self::ChecksumInvalid => StageId::ChecksumInvalid,
        }
    }
}

fn final_emit_suppression_stage(
    detector_id: &str,
    credential: &str,
    code_context: crate::context::CodeContext,
    confidence: f64,
    min_confidence_floor: f64,
    penalize_test_paths: bool,
) -> Option<StageId> {
    let context_hard_suppression_applies =
        penalize_test_paths || matches!(code_context, crate::context::CodeContext::Comment);
    if context_hard_suppression_applies && code_context.should_hard_suppress(confidence) {
        return Some(StageId::HardSuppressedContext);
    }

    if confidence < min_confidence_floor {
        if crate::detector_ids::is_generic_detector(detector_id) {
            if crate::confidence::known_prefix_confidence_floor(credential).is_some()
                && !crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential)
            {
                return Some(StageId::ProbabilisticGateNotPromising);
            }
            return Some(StageId::GenericBelowMinConfidence);
        }
        return Some(StageId::BelowMinConfidence);
    }

    None
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FinalEmitSignals<'a> {
    detector_id: &'a str,
    code_context: crate::context::CodeContext,
    confidence: f64,
    min_confidence_floor: f64,
    penalize_test_paths: bool,
}

impl<'a> FinalEmitSignals<'a> {
    pub(crate) const fn new(
        detector_id: &'a str,
        code_context: crate::context::CodeContext,
        confidence: f64,
        min_confidence_floor: f64,
        penalize_test_paths: bool,
    ) -> Self {
        Self {
            detector_id,
            code_context,
            confidence,
            min_confidence_floor,
            penalize_test_paths,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ReportAdjudicationPolicy<'a> {
    pub(crate) detector_id: &'a str,
    pub(crate) code_context: crate::context::CodeContext,
    pub(crate) confidence: f64,
    pub(crate) min_confidence_floor: f64,
    pub(crate) penalize_test_paths: bool,
    pub(crate) file_path: Option<&'a str>,
    pub(crate) is_named_detector: bool,
    pub(crate) allow_encoded_text_lift: bool,
    pub(crate) calibration: Option<&'a keyhog_core::Calibration>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MatchCtx<'a> {
    explicit_stage: Option<StageId>,
    process_signals: Option<ProcessCandidateSignals>,
    generic_bridge_signal: Option<GenericBridgeSignal>,
    entropy_fallback_signal: Option<EntropyFallbackSignal>,
    hot_pattern_signal: Option<HotPatternSignal>,
    entropy_generation_signal: Option<EntropyGenerationSignal>,
    named_detector_suppression: Option<NamedDetectorSuppressionCtx<'a>>,
    final_emit_signals: Option<FinalEmitSignals<'a>>,
}

impl<'a> MatchCtx<'a> {
    #[cfg(any(feature = "simdsieve", test))]
    pub(crate) const fn for_stage(stage_id: StageId) -> Self {
        Self {
            explicit_stage: Some(stage_id),
            process_signals: None,
            generic_bridge_signal: None,
            entropy_fallback_signal: None,
            hot_pattern_signal: None,
            entropy_generation_signal: None,
            named_detector_suppression: None,
            final_emit_signals: None,
        }
    }

    pub(crate) const fn for_process_signals(process_signals: ProcessCandidateSignals) -> Self {
        Self {
            explicit_stage: None,
            process_signals: Some(process_signals),
            generic_bridge_signal: None,
            entropy_fallback_signal: None,
            hot_pattern_signal: None,
            entropy_generation_signal: None,
            named_detector_suppression: None,
            final_emit_signals: None,
        }
    }

    pub(crate) const fn for_generic_bridge(signal: GenericBridgeSignal) -> Self {
        Self {
            explicit_stage: None,
            process_signals: None,
            generic_bridge_signal: Some(signal),
            entropy_fallback_signal: None,
            hot_pattern_signal: None,
            entropy_generation_signal: None,
            named_detector_suppression: None,
            final_emit_signals: None,
        }
    }

    pub(crate) const fn for_entropy_fallback(signal: EntropyFallbackSignal) -> Self {
        Self {
            explicit_stage: None,
            process_signals: None,
            generic_bridge_signal: None,
            entropy_fallback_signal: Some(signal),
            hot_pattern_signal: None,
            entropy_generation_signal: None,
            named_detector_suppression: None,
            final_emit_signals: None,
        }
    }

    pub(crate) const fn for_hot_pattern(signal: HotPatternSignal) -> Self {
        Self {
            explicit_stage: None,
            process_signals: None,
            generic_bridge_signal: None,
            entropy_fallback_signal: None,
            hot_pattern_signal: Some(signal),
            entropy_generation_signal: None,
            named_detector_suppression: None,
            final_emit_signals: None,
        }
    }

    pub(crate) const fn for_entropy_generation(signal: EntropyGenerationSignal) -> Self {
        Self {
            explicit_stage: None,
            process_signals: None,
            generic_bridge_signal: None,
            entropy_fallback_signal: None,
            hot_pattern_signal: None,
            entropy_generation_signal: Some(signal),
            named_detector_suppression: None,
            final_emit_signals: None,
        }
    }

    pub(crate) const fn for_named_detector(ctx: NamedDetectorSuppressionCtx<'a>) -> Self {
        Self {
            explicit_stage: None,
            process_signals: None,
            generic_bridge_signal: None,
            entropy_fallback_signal: None,
            hot_pattern_signal: None,
            entropy_generation_signal: None,
            named_detector_suppression: Some(ctx),
            final_emit_signals: None,
        }
    }

    pub(crate) const fn for_final_emit(signals: FinalEmitSignals<'a>) -> Self {
        Self {
            explicit_stage: None,
            process_signals: None,
            generic_bridge_signal: None,
            entropy_fallback_signal: None,
            hot_pattern_signal: None,
            entropy_generation_signal: None,
            named_detector_suppression: None,
            final_emit_signals: Some(signals),
        }
    }
}

type StageFn = for<'candidate, 'ctx, 'borrow> fn(
    CandidateMatch<'candidate>,
    &'borrow MatchCtx<'ctx>,
) -> StageOutcome;

const STAGES: &[StageFn] = &[
    explicit_stage,
    process_signal_stage,
    generic_bridge_stage,
    entropy_fallback_stage,
    hot_pattern_stage,
    entropy_generation_stage,
    named_detector_suppression_stage,
    final_emit_stage,
];

pub(crate) fn adjudicate_match(candidate: CandidateMatch<'_>, ctx: &MatchCtx<'_>) -> Verdict {
    for stage in STAGES {
        match stage(candidate, ctx) {
            StageOutcome::Pass => {}
            StageOutcome::Suppress(stage_id) => return Verdict::Suppressed(stage_id),
        }
    }
    Verdict::Reported(ctx.final_emit_signals.map(|signals| signals.confidence))
}

pub(crate) fn record_suppression(
    path: Option<&str>,
    credential: &str,
    ctx: &MatchCtx<'_>,
) -> Option<StageId> {
    let stage_id = adjudicate_match(CandidateMatch::new(credential), ctx).suppressed_stage();
    if let Some(stage_id) = stage_id {
        crate::telemetry::record_shape_suppression(path, credential, stage_id.as_str());
    }
    stage_id
}

pub(crate) fn record_checksum_invalid_suppression(
    path: Option<&str>,
    credential: &str,
) -> Option<StageId> {
    let ctx = MatchCtx::for_process_signals(ProcessCandidateSignals::from_checksum_invalid(true));
    record_suppression(path, credential, &ctx)
}

pub(crate) fn finalize_report_candidate(
    path: Option<&str>,
    credential: &str,
    policy: ReportAdjudicationPolicy<'_>,
) -> Option<f64> {
    let Some(confidence) = crate::confidence::policy::finalize_report_confidence(
        policy.confidence,
        crate::confidence::policy::ReportConfidencePolicy {
            credential,
            detector_id: policy.detector_id,
            file_path: policy.file_path,
            is_named_detector: policy.is_named_detector,
            penalize_test_paths: policy.penalize_test_paths,
            allow_encoded_text_lift: policy.allow_encoded_text_lift,
            calibration: policy.calibration,
        },
    ) else {
        record_checksum_invalid_suppression(path, credential);
        return None;
    };

    let final_emit_ctx = MatchCtx::for_final_emit(FinalEmitSignals::new(
        policy.detector_id,
        policy.code_context,
        confidence,
        policy.min_confidence_floor,
        policy.penalize_test_paths,
    ));
    match adjudicate_match(CandidateMatch::new(credential), &final_emit_ctx) {
        Verdict::Suppressed(stage_id) => {
            crate::telemetry::record_shape_suppression(path, credential, stage_id.as_str());
            None
        }
        Verdict::Reported(confidence) => confidence,
    }
}

pub(crate) fn finalize_report_raw_match(
    mut raw_match: RawMatch,
    policy: ReportAdjudicationPolicy<'_>,
) -> Option<RawMatch> {
    let credential = raw_match.credential.as_ref();
    let confidence =
        finalize_report_candidate(raw_match.location.file_path.as_deref(), credential, policy)?;
    raw_match.confidence = Some(confidence);
    Some(raw_match)
}

pub(crate) fn record_example_suppression(
    detector: &str,
    path: Option<&str>,
    credential: &str,
    reason: &'static str,
) {
    crate::telemetry::record_example_suppression(detector, path, credential, reason);
}

pub(crate) fn record_match_example_suppression(
    m: &RawMatch,
    fallback_path: Option<&str>,
    reason: &'static str,
) {
    record_example_suppression(
        m.detector_id.as_ref(),
        m.location.file_path.as_deref().or(fallback_path),
        m.credential.as_ref(),
        reason,
    );
}

fn explicit_stage(_candidate: CandidateMatch<'_>, ctx: &MatchCtx<'_>) -> StageOutcome {
    if let Some(stage_id) = ctx.explicit_stage {
        StageOutcome::Suppress(stage_id)
    } else {
        StageOutcome::Pass
    }
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

fn generic_bridge_stage(_candidate: CandidateMatch<'_>, ctx: &MatchCtx<'_>) -> StageOutcome {
    if let Some(signal) = ctx.generic_bridge_signal {
        StageOutcome::Suppress(signal.stage_id())
    } else {
        StageOutcome::Pass
    }
}

fn entropy_fallback_stage(_candidate: CandidateMatch<'_>, ctx: &MatchCtx<'_>) -> StageOutcome {
    if let Some(signal) = ctx.entropy_fallback_signal {
        StageOutcome::Suppress(signal.stage_id())
    } else {
        StageOutcome::Pass
    }
}

fn hot_pattern_stage(_candidate: CandidateMatch<'_>, ctx: &MatchCtx<'_>) -> StageOutcome {
    if let Some(signal) = ctx.hot_pattern_signal {
        StageOutcome::Suppress(signal.stage_id())
    } else {
        StageOutcome::Pass
    }
}

fn entropy_generation_stage(_candidate: CandidateMatch<'_>, ctx: &MatchCtx<'_>) -> StageOutcome {
    if let Some(signal) = ctx.entropy_generation_signal {
        StageOutcome::Suppress(signal.stage_id())
    } else {
        StageOutcome::Pass
    }
}

fn named_detector_suppression_stage(
    candidate: CandidateMatch<'_>,
    ctx: &MatchCtx<'_>,
) -> StageOutcome {
    let Some(suppression_ctx) = ctx.named_detector_suppression else {
        return StageOutcome::Pass;
    };
    if let Some(stage_id) = crate::suppression::suppress_named_detector_finding_stage(
        candidate.credential(),
        suppression_ctx,
    ) {
        return StageOutcome::Suppress(stage_id);
    }
    StageOutcome::Pass
}

fn final_emit_stage(candidate: CandidateMatch<'_>, ctx: &MatchCtx<'_>) -> StageOutcome {
    let Some(signals) = ctx.final_emit_signals else {
        return StageOutcome::Pass;
    };
    if let Some(stage_id) = final_emit_suppression_stage(
        signals.detector_id,
        candidate.credential(),
        signals.code_context,
        signals.confidence,
        signals.min_confidence_floor,
        signals.penalize_test_paths,
    ) {
        return StageOutcome::Suppress(stage_id);
    }
    StageOutcome::Pass
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
