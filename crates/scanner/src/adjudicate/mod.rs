//! Single candidate-adjudication funnel.
//!
//! Emission paths find candidate values. This module decides whether a candidate
//! is reportable and names the stage that made the decision.

mod entropy;
pub(crate) mod generic;
mod stage;

use crate::suppression::NamedDetectorSuppressionCtx;
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
        detector_id: &str,
        detector_min_len: Option<usize>,
        credential_shape: Option<&crate::credential_shapes::CredentialShapeRule>,
        credential: &str,
        data: &str,
        credential_start: usize,
        match_end: usize,
    ) -> Self {
        if credential_shape.is_some_and(|shape| !shape.allows(credential)) {
            return Self::suppress(StageId::DetectorCredentialShapeInvalid);
        }
        if crate::pipeline::is_within_hex_context(data, credential_start, match_end) {
            return Self::suppress(StageId::WithinHexContext);
        }
        if is_hex_digest_fragment(
            detector_min_len,
            data,
            credential_start,
            match_end,
            credential,
        ) {
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

    pub(crate) fn from_checksum_policy(credential: &str) -> Self {
        Self::from_checksum_invalid(
            crate::confidence::policy::checksum_policy_for(credential).is_invalid(),
        )
    }

    pub(crate) fn from_process_entropy_shape(
        is_generic: bool,
        is_weakly_anchored: bool,
        entropy: f64,
        entropy_threshold: f64,
        floor_detector: Option<&keyhog_core::DetectorSpec>,
        credential: &str,
    ) -> Self {
        if !(is_generic || is_weakly_anchored) {
            return Self::pass();
        }
        Self::from_entropy_shape(
            generic_entropy_below_floor(
                entropy,
                entropy_threshold,
                floor_detector,
                credential.len(),
            ),
            crate::suppression::shape::looks_like_camel_case_no_digit(credential),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HotPatternSignal {
    ShapeGate(&'static str),
}

impl HotPatternSignal {
    const fn stage_id(self) -> StageId {
        match self {
            Self::ShapeGate(reason) => StageId::ShapeGate(reason),
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

    // `min_confidence_floor` is resolved from the ACTIVE detector corpus by the
    // producer. Never re-read the embedded registry here: custom detector specs
    // and operator overrides may differ from the embedded copy, and a second
    // lookup would silently replace the policy that actually compiled.
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

pub(crate) fn detector_min_confidence_floor(
    detector_floor: Option<f64>,
    default_floor: f64,
) -> f64 {
    detector_floor.unwrap_or(default_floor) // LAW10: absent detector floor => explicit Tier-A scan default floor, recall-safe
}

/// The compiled default for the Tier-A `entropy_threshold` knob. Single-sourced
/// from `keyhog_core::DEFAULT_ENTROPY_THRESHOLD` so this fallback and
/// `ScanConfig::default().entropy_threshold` can never drift apart (they were two
/// hand-kept `4.5` literals before).
use keyhog_core::DEFAULT_ENTROPY_THRESHOLD as DEFAULT_GENERIC_ENTROPY_THRESHOLD;

/// Recall-safe base floor for a detector that declares no length-bucketed
/// `entropy_floor`. Detector TOMLs override this through the active spec passed
/// by the compiled scanner; no embedded registry or parallel floor table exists.
const DEFAULT_GENERIC_ENTROPY_FLOOR: f64 = 3.5;

/// Single source of truth for the generic-detector entropy gate used by named
/// generic/weak-anchor processing and the generic-secret fallback bridge.
///
/// The per-family, length-bucketed base floors are Tier-B calibration data owned
/// in each generic detector's TOML `entropy_floor` field. The active spec is
/// passed directly from the compiled scanner; this owner layers only the Tier-A
/// `entropy_threshold` knob on top. An operator can raise the floor above the
/// detector calibration for a stricter scan but cannot silently replace it.
pub(crate) fn generic_entropy_floor(
    entropy_threshold: f64,
    detector: Option<&keyhog_core::DetectorSpec>,
    credential_len: usize,
) -> f64 {
    let base = detector
        .and_then(|spec| {
            spec.entropy_floor
                .iter()
                .find(|bucket| bucket.max_len.is_none_or(|max| credential_len <= max))
        })
        .map_or(DEFAULT_GENERIC_ENTROPY_FLOOR, |bucket| bucket.floor);

    let threshold_val = detector
        .and_then(|s| s.entropy_high)
        .map_or(DEFAULT_GENERIC_ENTROPY_THRESHOLD, |threshold| threshold);

    if entropy_threshold.is_finite() && entropy_threshold > threshold_val {
        base.max(entropy_threshold)
    } else {
        base
    }
}

pub(crate) fn generic_entropy_below_floor(
    entropy: f64,
    entropy_threshold: f64,
    detector: Option<&keyhog_core::DetectorSpec>,
    credential_len: usize,
) -> bool {
    entropy < generic_entropy_floor(entropy_threshold, detector, credential_len)
}

pub(crate) fn generic_bridge_entropy_below_floor(
    entropy: f64,
    entropy_threshold: f64,
    generic_keyword_low_entropy: bool,
    generic_secret_detector: Option<&keyhog_core::DetectorSpec>,
    generic_keyword_detector: Option<&keyhog_core::DetectorSpec>,
    credential_len: usize,
) -> bool {
    let detector = if generic_keyword_low_entropy {
        generic_keyword_detector
    } else {
        generic_secret_detector
    };
    generic_entropy_below_floor(entropy, entropy_threshold, detector, credential_len)
}

/// Resolved shape-gate parameters of the `generic-secret` detector: its
/// configured minimum credential length, with the engine's historical fallback
/// (`8`) when the spec omits it. (The detector's `entropy_high` is a
/// confidence-boost threshold read directly from the spec where confidence is
/// scored; the base64 value-shape gates own their OWN `HIGH_ENTROPY_BASE64_CUTOFF`
/// and never borrow this one — the two must not be conflated.)
#[derive(Debug, Clone, Copy)]
pub(crate) struct GenericSecretShapeFloors {
    pub(crate) min_len: usize,
}

/// Select the `generic-secret` detector from the ACTIVE detector set and read its
/// shape-gate floors. This owns the generic-secret floor VALUE so the generic
/// value-shape leaf never names the detector id itself — the
/// `suppression_named_detector_ctx_owner` gate requires generic floor policy to
/// live in adjudicate, not in engine leaves (ONE PLACE). The `GENERIC_SECRET`
/// detector is resolved ONCE at scanner build through the shared compiled
/// [`crate::generic_keyword_owner::GenericOwningDetectorIndex`] (the single owner
/// of the `id == GENERIC_SECRET` selection) and passed in here, replacing a
/// per-candidate linear `detectors.iter().find(...)`. `None` (no GENERIC_SECRET
/// detector loaded) yields the literal default floor, identical to the old
/// `find(...)` returning `None`.
pub(crate) fn generic_secret_shape_floors(
    generic_secret: Option<&keyhog_core::DetectorSpec>,
) -> GenericSecretShapeFloors {
    GenericSecretShapeFloors {
        min_len: generic_secret
            .and_then(|s| s.min_len)
            .map_or(8, |min_len| min_len),
    }
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
        // dogfood-event dedup slot first — NOT a generic shape event. Recording a
        // shape event here too would claim the slot first and dedup the example
        // event away, leaving the trace mislabeled `shape_suppressed` (KH-GAP-091).
        record_example_suppression("pipeline", path, credential, reason);
        return;
    }
    crate::telemetry::record_shape_suppression(path, credential, reason);
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

/// A decoded sub-chunk is SYNTHESIZED content — the bytes that fall out of a
/// base64/hex/url/reverse decode, with NO surrounding keyword or structural
/// context from the real file. A generic/entropy detector fires on shape/entropy
/// ALONE, so on decoded content its "evidence" is nothing but the decoded bytes
/// happening to look token-shaped. Decoding ordinary readable text routinely
/// produces exactly that: exception names (`InvalidNextTokenException"}`), HTTP
/// headers (`max-age1536000;includeSubdomains;preload`), library prose
/// (`PythonlibraryimplementingthefullGithubAPIv3`), XML paths, `OAuth2.0`. On the
/// full CredData tree, decode-through surfaced +264 such generic/entropy hits
/// that are ALL non-secrets (measured decode-on−decode-off diff), for ~0 real
/// TP — pure precision loss. A decoded match must carry its OWN structural
/// evidence — a required vendor literal / anchored slot that survives the decode
/// — to be trusted (KH-L-0404 "anchor decoded matches"). The generic/entropy
/// family has none. Vendor/key detectors on decoded content (genuine encoded
/// secrets — backblaze/confluent/wordpress tokens, `-----BEGIN`-headed key
/// bodies) self-anchor on their required literal and are UNAFFECTED: this gate
/// keys on the detector id only, never the value. Scoped to the decode path
/// (`#[cfg(feature = "decode")]`) — top-level generic/entropy matches, which DO
/// have real file context, are untouched.
#[cfg(feature = "decode")]
pub(crate) fn record_decoded_generic_entropy_suppression(
    m: &RawMatch,
    fallback_path: Option<&str>,
) -> bool {
    if crate::detector_ids::is_generic_or_entropy_detector(m.detector_id.as_ref()) {
        record_match_example_suppression(m, fallback_path, "decoded_generic_entropy_unanchored");
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
