//! Single candidate-adjudication funnel.
//!
//! Emission paths find candidate values. This module decides whether a candidate
//! is reportable and names the stage that made the decision.

mod entropy;
pub(crate) mod generic;
mod stage;

use crate::suppression::NamedDetectorSuppressionCtx;
#[cfg(any(feature = "decode", feature = "ml"))]
use keyhog_core::RawMatch;

#[cfg(feature = "entropy")]
pub(crate) use entropy::entropy_fallback_example_suppression_stage;
pub(crate) use entropy::{EntropyFallbackSignal, EntropyGenerationSignal, EntropyShapeStage};
pub(crate) use generic::{
    generic_bridge_bare_auth_rejected, generic_bridge_canonical_hex_placeholder_stage,
    generic_bridge_keyword_boundary_rejected, GenericBridgeSignal, GenericValueShapeStage,
};
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
        is_generic_detector: bool,
        detector_length: crate::detector_execution_policy::CompiledDetectorLengthPolicy,
        credential_shape: Option<&crate::credential_shapes::CredentialShapeRule>,
        degenerate_run_min_length: usize,
        credential: &str,
        data: &str,
        credential_start: usize,
        match_end: usize,
    ) -> Self {
        match detector_length.rejection(credential.len()) {
            Some(crate::detector_execution_policy::CandidateLengthRejection::TooShort) => {
                return Self::suppress(StageId::BelowDetectorMinLength);
            }
            Some(crate::detector_execution_policy::CandidateLengthRejection::TooLong) => {
                return Self::suppress(StageId::AboveDetectorMaxLength);
            }
            None => {}
        }
        if credential_shape.is_some_and(|shape| !shape.allows(credential)) {
            return Self::suppress(StageId::DetectorCredentialShapeInvalid);
        }
        if crate::pipeline::is_within_hex_context(data, credential_start, match_end) {
            return Self::suppress(StageId::WithinHexContext);
        }
        if is_hex_digest_fragment(
            detector_length.min_len,
            data,
            credential_start,
            match_end,
            credential,
        ) {
            return Self::suppress(StageId::HexDigestFragment);
        }
        if is_generic_detector
            && crate::confidence::known_prefix_confidence_floor(
                credential,
                degenerate_run_min_length,
            )
            .is_none()
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

    pub(crate) fn from_process_entropy_shape(
        is_generic: bool,
        is_weakly_anchored: bool,
        entropy: f64,
        effective_entropy_floor: Option<f64>,
        credential: &str,
    ) -> Self {
        if !(is_generic || is_weakly_anchored) {
            return Self::pass();
        }
        let Some(entropy_floor) = effective_entropy_floor else {
            return Self::suppress(StageId::EntropyPolicyUnavailable);
        };
        Self::from_entropy_shape(
            entropy < entropy_floor,
            crate::suppression::shape::looks_like_camel_case_no_digit(credential),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "simdsieve")]
pub(crate) enum HotPatternSignal {
    ShapeGate(&'static str),
}

#[cfg(feature = "simdsieve")]
impl HotPatternSignal {
    const fn stage_id(self) -> StageId {
        match self {
            Self::ShapeGate(reason) => StageId::ShapeGate(reason),
        }
    }
}

fn final_emit_suppression_stage(
    is_generic_detector: bool,
    credential: &str,
    code_context: crate::context::CodeContext,
    confidence: f64,
    min_confidence_floor: f64,
    penalize_test_paths: bool,
    degenerate_run_min_length: usize,
    context_suppression_threshold: Option<f64>,
) -> Option<StageId> {
    let context_hard_suppression_applies =
        penalize_test_paths || matches!(code_context, crate::context::CodeContext::Comment);
    if context_hard_suppression_applies
        && context_suppression_threshold.is_some_and(|threshold| confidence < threshold)
    {
        return Some(StageId::HardSuppressedContext);
    }

    // `min_confidence_floor` is resolved from the ACTIVE detector corpus by the
    // producer. Never re-read the embedded registry here: custom detector specs
    // and operator overrides may differ from the embedded copy, and a second
    // lookup would silently replace the policy that actually compiled.
    if confidence < min_confidence_floor {
        if is_generic_detector {
            if crate::confidence::known_prefix_confidence_floor(
                credential,
                degenerate_run_min_length,
            )
            .is_some()
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
pub(crate) struct FinalEmitSignals {
    is_generic_detector: bool,
    code_context: crate::context::CodeContext,
    confidence: f64,
    min_confidence_floor: f64,
    penalize_test_paths: bool,
    degenerate_run_min_length: usize,
    context_suppression_threshold: Option<f64>,
}

impl FinalEmitSignals {
    #[cfg(test)]
    pub(crate) const fn new(
        is_generic_detector: bool,
        code_context: crate::context::CodeContext,
        confidence: f64,
        min_confidence_floor: f64,
        degenerate_run_min_length: usize,
        penalize_test_paths: bool,
    ) -> Self {
        Self::with_context_suppression_threshold(
            is_generic_detector,
            code_context,
            confidence,
            min_confidence_floor,
            degenerate_run_min_length,
            penalize_test_paths,
            code_context.hard_suppression_threshold(),
        )
    }

    pub(crate) const fn with_context_suppression_threshold(
        is_generic_detector: bool,
        code_context: crate::context::CodeContext,
        confidence: f64,
        min_confidence_floor: f64,
        degenerate_run_min_length: usize,
        penalize_test_paths: bool,
        context_suppression_threshold: Option<f64>,
    ) -> Self {
        Self {
            is_generic_detector,
            code_context,
            confidence,
            min_confidence_floor,
            degenerate_run_min_length,
            penalize_test_paths,
            context_suppression_threshold,
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
    pub(crate) context_suppression_threshold: Option<f64>,
    pub(crate) post_match: keyhog_core::DetectorPostMatchConfidenceSpec,
    pub(crate) file_path: Option<&'a str>,
    pub(crate) is_named_detector: bool,
    /// Compiled from the active detector's TOML `kind = "phase2-generic"`, or
    /// known directly from the synthetic entropy producer. Finalization must
    /// not infer detector behavior from an ID prefix.
    pub(crate) is_generic_detector: bool,
    pub(crate) allow_encoded_text_lift: bool,
    pub(crate) allow_canonical_hex_key: bool,
    pub(crate) checksum: crate::checksum::ChecksumConfidenceDecision,
    pub(crate) calibration: Option<&'a keyhog_core::Calibration>,
}

pub(crate) fn detector_min_confidence_floor(
    detector_floor: Option<f64>,
    default_floor: f64,
) -> f64 {
    detector_floor.unwrap_or(default_floor) // LAW10: absent detector floor => explicit Tier-A scan default floor, recall-safe
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MatchCtx<'a> {
    explicit_stage: Option<StageId>,
    process_signals: Option<ProcessCandidateSignals>,
    generic_bridge_signal: Option<GenericBridgeSignal>,
    entropy_fallback_signal: Option<EntropyFallbackSignal>,
    #[cfg(feature = "simdsieve")]
    hot_pattern_signal: Option<HotPatternSignal>,
    entropy_generation_signal: Option<EntropyGenerationSignal>,
    named_detector_suppression: Option<NamedDetectorSuppressionCtx<'a>>,
    final_emit_signals: Option<FinalEmitSignals>,
}

impl<'a> MatchCtx<'a> {
    pub(crate) const fn for_stage(stage_id: StageId) -> Self {
        Self {
            explicit_stage: Some(stage_id),
            process_signals: None,
            generic_bridge_signal: None,
            entropy_fallback_signal: None,
            #[cfg(feature = "simdsieve")]
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
            #[cfg(feature = "simdsieve")]
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
            #[cfg(feature = "simdsieve")]
            hot_pattern_signal: None,
            entropy_generation_signal: None,
            named_detector_suppression: None,
            final_emit_signals: None,
        }
    }

    #[cfg(feature = "entropy")]
    pub(crate) const fn for_entropy_fallback(signal: EntropyFallbackSignal) -> Self {
        Self {
            explicit_stage: None,
            process_signals: None,
            generic_bridge_signal: None,
            entropy_fallback_signal: Some(signal),
            #[cfg(feature = "simdsieve")]
            hot_pattern_signal: None,
            entropy_generation_signal: None,
            named_detector_suppression: None,
            final_emit_signals: None,
        }
    }

    #[cfg(feature = "simdsieve")]
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
            #[cfg(feature = "simdsieve")]
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
            #[cfg(feature = "simdsieve")]
            hot_pattern_signal: None,
            entropy_generation_signal: None,
            named_detector_suppression: Some(ctx),
            final_emit_signals: None,
        }
    }

    pub(crate) const fn for_final_emit(signals: FinalEmitSignals) -> Self {
        Self {
            explicit_stage: None,
            process_signals: None,
            generic_bridge_signal: None,
            entropy_fallback_signal: None,
            #[cfg(feature = "simdsieve")]
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
    #[cfg(feature = "simdsieve")]
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
        record_suppression_telemetry(path, credential, stage_id);
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

pub(crate) fn record_missing_required_companion_suppression(
    path: Option<&str>,
    credential: &str,
) -> Option<StageId> {
    let ctx = MatchCtx::for_process_signals(
        ProcessCandidateSignals::from_missing_required_companion(true),
    );
    let recorded = record_suppression(path, credential, &ctx);
    debug_assert_eq!(recorded, Some(StageId::MissingRequiredCompanion));
    recorded
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
            allow_canonical_hex_key: policy.allow_canonical_hex_key,
            checksum: policy.checksum,
            calibration: policy.calibration,
            post_match: policy.post_match,
        },
    ) else {
        record_checksum_invalid_suppression(path, credential);
        return None;
    };

    let final_emit_ctx =
        MatchCtx::for_final_emit(FinalEmitSignals::with_context_suppression_threshold(
            policy.is_generic_detector,
            policy.code_context,
            confidence,
            policy.min_confidence_floor,
            policy.post_match.degenerate_run_min_length,
            policy.penalize_test_paths,
            policy.context_suppression_threshold,
        ));
    match adjudicate_match(CandidateMatch::new(credential), &final_emit_ctx) {
        Verdict::Suppressed(stage_id) => {
            record_suppression_telemetry(path, credential, stage_id);
            None
        }
        Verdict::Reported(confidence) => confidence,
    }
}

fn record_suppression_telemetry(path: Option<&str>, credential: &str, stage_id: StageId) {
    let reason = stage_id.as_str();
    if reason == "contains_EXAMPLE_token" {
        // The example-token gate is the MOST informative reason for a placeholder
        // drop ("this is a known EXAMPLE token"). Record it as an EXAMPLE
        // suppression (kind `example_suppressed`) so it claims the per-credential
        // dogfood-event dedup slot first. NOT a generic shape event. Recording a
        // shape event here too would claim the slot first and dedup the example
        // event away, leaving the trace mislabeled `shape_suppressed` (KH-GAP-091).
        record_example_suppression("pipeline", path, credential, reason);
        return;
    }
    crate::telemetry::record_shape_suppression(path, credential, reason);
}

#[cfg(feature = "ml")]
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

#[cfg(feature = "decode")]
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

#[cfg(feature = "decode")]
pub(crate) fn record_decoded_parent_example_suppression(
    m: &RawMatch,
    fallback_path: Option<&str>,
    parent_data: &str,
) -> bool {
    if crate::context::is_known_example_credential(&m.credential)
        && parent_data.contains(m.credential.as_ref())
    {
        record_match_example_suppression(m, fallback_path, "decoded_parent_example");
        true
    } else {
        false
    }
}

#[cfg(feature = "decode")]
pub(crate) fn record_decoded_reverse_placeholder_suppression(
    m: &RawMatch,
    fallback_path: Option<&str>,
    decoded_source_type: &str,
) -> bool {
    if !decoded_source_type.contains("/reverse") {
        return false;
    }
    let reversed = crate::decode::reverse::reverse_str(&m.credential).to_uppercase();
    if decoded_reverse_placeholder_marker(&reversed) {
        record_match_example_suppression(m, fallback_path, "decoded_reverse_placeholder");
        true
    } else {
        false
    }
}

#[cfg(feature = "decode")]
fn decoded_reverse_placeholder_marker(reversed: &str) -> bool {
    reversed.contains("EXAMPLE")
        || reversed.contains("PLACEHOLDER")
        || reversed.contains("SAMPLE")
        || reversed.contains("YOUR_")
}

/// Suppress entropy-only findings on synthesized decoded content. The caller
/// supplies the active plan's detector class because IDs and service labels do
/// not own execution semantics. Phase-2 generic detectors are deliberately not
/// included: they fire only when the decoded plaintext (or the bounded parent
/// splice) retains a detector-owned assignment keyword such as `secret=` or
/// `api_key=`. Discarding those anchored matches lost real base64/hex/URL-wrapped
/// contract positives. Vendor detectors remain self-anchoring as before.
#[cfg(feature = "decode")]
pub(crate) fn record_decoded_unanchored_entropy_suppression(
    m: &RawMatch,
    fallback_path: Option<&str>,
    is_entropy: bool,
) -> bool {
    if is_entropy {
        record_match_example_suppression(m, fallback_path, "decoded_entropy_unanchored");
        true
    } else {
        false
    }
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

#[cfg(feature = "simdsieve")]
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
        signals.is_generic_detector,
        candidate.credential(),
        signals.code_context,
        signals.confidence,
        signals.min_confidence_floor,
        signals.penalize_test_paths,
        signals.degenerate_run_min_length,
        signals.context_suppression_threshold,
    ) {
        return StageOutcome::Suppress(stage_id);
    }
    StageOutcome::Pass
}

pub(crate) fn is_hex_digest_fragment(
    detector_min_len: Option<usize>,
    data: &str,
    start: usize,
    end: usize,
    credential: &str,
) -> bool {
    let min_len = detector_min_len.map_or(16, |min_len| min_len);
    if credential.len() < min_len || !credential.bytes().all(|b| b.is_ascii_hexdigit()) {
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
