use crate::context;

pub(crate) enum MlScoreResult {
    /// Score is final and the match can be pushed immediately.
    Final(f64),
    #[cfg(feature = "ml")]
    /// ML scoring is batched at the end of the scan.
    Pending {
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        mode: crate::detector_ml_policy::ActiveMlMode,
    },
}

pub(crate) type CredentialChecksumPolicy = crate::checksum::ChecksumConfidenceDecision;

#[inline]
pub(crate) fn checksum_policy_for(credential: &str) -> CredentialChecksumPolicy {
    crate::checksum::ChecksumConfidenceDecision::for_credential(credential)
}

#[inline]
pub(crate) fn apply_checksum_confidence(confidence: f64, credential: &str) -> Option<f64> {
    apply_checksum_decision_confidence(confidence, checksum_policy_for(credential))
}

#[inline]
pub(crate) fn apply_checksum_decision_confidence(
    confidence: f64,
    decision: CredentialChecksumPolicy,
) -> Option<f64> {
    match decision.result() {
        crate::checksum::ChecksumResult::Invalid => None,
        crate::checksum::ChecksumResult::Valid => Some(
            confidence.max(
                decision
                    .valid_confidence_floor()
                    .unwrap_or(crate::checksum::CHECKSUM_VALID_FLOOR),
            ),
        ),
        crate::checksum::ChecksumResult::StructurallyValid => Some(confidence),
        crate::checksum::ChecksumResult::NotApplicable => Some(confidence),
    }
}

pub(crate) fn apply_known_prefix_floor(confidence: f64, credential: &str) -> f64 {
    if let Some(floor) = crate::confidence::known_prefix_confidence_floor(credential) {
        confidence.max(floor)
    } else {
        confidence
    }
}

pub(crate) fn pre_ml_heuristic_confidence(
    raw_confidence: f64,
    code_context: context::CodeContext,
    penalize_test_paths: bool,
) -> f64 {
    let context_multiplier = match code_context {
        context::CodeContext::TestCode | context::CodeContext::Documentation
            if !penalize_test_paths =>
        {
            1.0
        }
        _ => code_context.confidence_multiplier(),
    };
    raw_confidence * context_multiplier
}

pub(crate) struct MatchHeuristicConfidencePolicy {
    pub(crate) has_literal_prefix: bool,
    pub(crate) has_context_anchor: bool,
    pub(crate) entropy: f64,
    pub(crate) entropy_threshold: f64,
    pub(crate) keyword_nearby: bool,
    pub(crate) sensitive_file: bool,
    pub(crate) match_length: usize,
    pub(crate) has_companion: bool,
    pub(crate) code_context: context::CodeContext,
    pub(crate) penalize_test_paths: bool,
}

pub(crate) struct CandidateMatchScorePolicy<'a> {
    pub(crate) has_literal_prefix: bool,
    pub(crate) has_context_anchor: bool,
    pub(crate) entropy: f64,
    pub(crate) entropy_threshold: f64,
    pub(crate) keyword_nearby: bool,
    pub(crate) sensitive_file: bool,
    pub(crate) match_length: usize,
    pub(crate) has_companion: bool,
    pub(crate) code_context: context::CodeContext,
    pub(crate) penalize_test_paths: bool,
    #[cfg(feature = "ml")]
    pub(crate) ml_mode: Option<crate::detector_ml_policy::ActiveMlMode>,
    #[cfg(not(feature = "ml"))]
    pub(crate) ml_enabled: bool,
    pub(crate) credential: &'a str,
    /// Strong service match eligible for the structural anchor floor.
    pub(crate) is_named_detector: bool,
    /// Any non-generic service regex, including weakly anchored patterns.
    pub(crate) is_service_detector: bool,
    /// The matched pattern requires a distinctive literal infix (terraform
    /// `\.atlasv1\.`), a third anchor form alongside the keyword context anchor
    /// and the literal prefix, for named detectors that carry neither.
    pub(crate) has_distinctive_inner_literal: bool,
}

pub(crate) fn match_heuristic_confidence(policy: MatchHeuristicConfidencePolicy) -> f64 {
    let raw_confidence = crate::confidence::compute_confidence_with_threshold(
        &crate::confidence::ConfidenceSignals {
            has_literal_prefix: policy.has_literal_prefix,
            has_context_anchor: policy.has_context_anchor,
            entropy: policy.entropy,
            keyword_nearby: policy.keyword_nearby,
            sensitive_file: policy.sensitive_file,
            match_length: policy.match_length,
            has_companion: policy.has_companion,
        },
        policy.entropy_threshold,
    );
    pre_ml_heuristic_confidence(
        raw_confidence,
        policy.code_context,
        policy.penalize_test_paths,
    )
}

/// Baseline confidence guaranteed to a service-anchored ("named") detector whose
/// regex required a context anchor. Chosen to clear the default `min_confidence`
/// floor (`0.40`) with headroom for downstream path / calibration penalties,
/// while staying below the "high confidence" band so refinement signals
/// (entropy, companion, sensitive file) still differentiate above it.
pub(crate) const NAMED_DETECTOR_ANCHOR_FLOOR: f64 = 0.55;

/// Lift the heuristic confidence of a service-anchored detector match to
/// [`NAMED_DETECTOR_ANCHOR_FLOOR`] when the match carried a strong anchor, a
/// required keyword **context anchor** (capture group), a distinctive **literal
/// prefix** (`cs_`, `pl_`, `tk_`, `sk-`, `ghp_`), or a distinctive **required
/// literal infix** (terraform `\.atlasv1\.`, whose regex opens with a class and
/// captures the whole match so it carries neither of the other two), or an
/// independently matched companion. These signals are folded into the single
/// `has_anchor` argument by the caller.
///
/// `compute_confidence` is a *normalized* weighted sum: it divides the earned
/// signal weight by the full signal set (literal prefix, context anchor,
/// entropy, sensitive file, companion, keyword-nearby). A service detector that
/// earns ONLY the anchor weight. `CROWDIN_API_TOKEN = <40hex>` (context anchor)
/// or a bare `cs_<34 alnum>` cloudsmith token (literal prefix), structurally
/// cannot earn the others, so its normalized score lands below the `0.40` floor
/// and the match is dropped as `below_min_confidence`, even though the match
/// *only fired because the service-specific anchor was present next to a value
/// of the contracted shape*. That anchor is itself positive evidence. This is
/// the single trust signal the previously-scattered shape / entropy / confidence
/// gates each failed to credit consistently.
///
/// FP-safe by construction: `is_named_detector` is `is_service_anchored_detector
/// && !weak_anchor`, so generic, entropy, private-key-fallback, and
/// collision-prone weak-anchor detectors are excluded upstream and keep the full
/// gate stack; `has_anchor` requires a real keyword group or an extractable
/// literal prefix (not a bare-value match). The lift is a floor (`max`), never a
/// cap, so stronger matches keep their higher score.
pub(crate) fn apply_named_detector_anchor_floor(
    confidence: f64,
    is_named_detector: bool,
    has_anchor: bool,
) -> f64 {
    // A NaN confidence is a broken upstream signal, never a real score. `f64::max`
    // IGNORES NaN, so `NaN.max(FLOOR)` would silently manufacture the anchor floor
    // from garbage, and an un-floored NaN would propagate to poison every
    // downstream `>=` gate (every comparison against NaN is false). Collapse NaN to
    // 0.0 first, loud in debug, fail-closed in release (Law 10), so a broken
    // score is never laundered into a mid-tier confidence nor leaked as NaN.
    debug_assert!(
        !confidence.is_nan(),
        "apply_named_detector_anchor_floor received NaN confidence, broken upstream score"
    );
    let confidence = if confidence.is_nan() { 0.0 } else { confidence };
    if is_named_detector && has_anchor {
        confidence.max(NAMED_DETECTOR_ANCHOR_FLOOR)
    } else {
        confidence
    }
}

pub(crate) fn candidate_match_score(policy: CandidateMatchScorePolicy<'_>) -> MlScoreResult {
    let heuristic_conf = match_heuristic_confidence(MatchHeuristicConfidencePolicy {
        has_literal_prefix: policy.has_literal_prefix,
        has_context_anchor: policy.has_context_anchor,
        entropy: policy.entropy,
        entropy_threshold: policy.entropy_threshold,
        keyword_nearby: policy.keyword_nearby,
        sensitive_file: policy.sensitive_file,
        match_length: policy.match_length,
        has_companion: policy.has_companion,
        code_context: policy.code_context,
        penalize_test_paths: policy.penalize_test_paths,
    });
    // An anchored service-detector match is positive evidence the normalized
    // signal sum structurally under-credits; lift it to clear the floor. The
    // anchor is a required keyword group (`has_context_anchor`), a distinctive
    // literal prefix (`has_literal_prefix`: `cs_`, `pl_`, `tk_`, bare service
    // tokens with no surrounding keyword), OR a distinctive required literal
    // infix (`has_distinctive_inner_literal`: terraform `\.atlasv1\.`, whose
    // regex opens with a class and captures the whole match so it carries
    // neither of the other two), OR a matched companion. Applied before the ML branch so it propagates
    // through both the heuristic-only `Final` path and the `Pending` path,
    // where the compiled detector-owned model mode determines its contribution.
    let heuristic_conf = apply_named_detector_anchor_floor(
        heuristic_conf,
        policy.is_named_detector,
        policy.has_context_anchor
            || policy.has_literal_prefix
            || policy.has_distinctive_inner_literal
            || policy.has_companion,
    );

    #[cfg(not(feature = "ml"))]
    let score_result = {
        let _ = (
            policy.ml_enabled,
            policy.is_named_detector,
            policy.is_service_detector,
        ); // cfg-only fields; heuristic confidence still emits without ML
        MlScoreResult::Final(heuristic_conf)
    };

    #[cfg(feature = "ml")]
    let score_result = {
        let Some(mode) = policy.ml_mode else {
            return MlScoreResult::Final(heuristic_conf);
        };
        if let Some(confidence) = probabilistic_promise_confidence_override(
            policy.credential,
            policy.is_service_detector,
            policy.has_companion,
        ) {
            MlScoreResult::Final(confidence)
        } else {
            MlScoreResult::Pending {
                heuristic_conf,
                code_context: policy.code_context,
                mode,
            }
        }
    };

    match score_result {
        MlScoreResult::Final(confidence) => {
            MlScoreResult::Final(apply_known_prefix_floor(confidence, policy.credential))
        }
        #[cfg(feature = "ml")]
        MlScoreResult::Pending { .. } => score_result,
    }
}

pub(crate) struct ReportConfidencePolicy<'a> {
    pub(crate) credential: &'a str,
    pub(crate) detector_id: &'a str,
    pub(crate) file_path: Option<&'a str>,
    pub(crate) is_named_detector: bool,
    pub(crate) penalize_test_paths: bool,
    pub(crate) allow_encoded_text_lift: bool,
    pub(crate) allow_canonical_hex_key: bool,
    pub(crate) checksum: CredentialChecksumPolicy,
    pub(crate) calibration: Option<&'a keyhog_core::Calibration>,
}

/// Canonical precision for the public confidence contract. GPU MoE kernels
/// accumulate `f32` values while the CPU reference promotes the same inputs to
/// `f64`; their mathematically equivalent scores can differ by a few ULPs.
/// Three decimal places preserve 1e-3 policy resolution while making serialized
/// confidence and the final threshold decision backend-invariant.
const REPORT_CONFIDENCE_SCALE: f64 = 1_000.0;

#[inline]
fn canonicalize_report_confidence(confidence: f64) -> f64 {
    (confidence * REPORT_CONFIDENCE_SCALE).round() / REPORT_CONFIDENCE_SCALE
}

pub(crate) fn finalize_report_confidence(
    confidence: f64,
    policy: ReportConfidencePolicy<'_>,
) -> Option<f64> {
    let confidence = crate::confidence::apply_post_ml_penalties_with_encoded_text_lift(
        confidence,
        policy.credential,
        policy.is_named_detector,
        policy.allow_encoded_text_lift,
        policy.allow_canonical_hex_key,
    );
    let confidence = crate::confidence::apply_path_confidence_penalties(
        confidence,
        policy.file_path,
        policy.penalize_test_paths,
    );
    let confidence = apply_known_prefix_floor(confidence, policy.credential);
    let confidence = crate::confidence::apply_calibration_multiplier(
        confidence,
        policy.detector_id,
        policy.calibration,
    );
    apply_checksum_decision_confidence(confidence, policy.checksum)
        .map(canonicalize_report_confidence)
}

#[cfg(feature = "ml")]
#[derive(Clone, Copy)]
pub(crate) struct MlConfidencePolicy {
    pub(crate) heuristic_confidence: f64,
    pub(crate) model_confidence: f64,
    pub(crate) ml_weight: f64,
    pub(crate) mode: crate::detector_ml_policy::ActiveMlMode,
    pub(crate) code_context: context::CodeContext,
    pub(crate) scan_comments: bool,
    pub(crate) penalize_test_paths: bool,
}

#[cfg(feature = "ml")]
pub(crate) fn ml_pending_confidence(policy: MlConfidencePolicy) -> f64 {
    let mut confidence = match policy.mode {
        crate::detector_ml_policy::ActiveMlMode::Lift => {
            policy.heuristic_confidence
                + policy.ml_weight
                    * (policy.model_confidence - policy.heuristic_confidence).max(0.0)
        }
        crate::detector_ml_policy::ActiveMlMode::Blend => {
            (policy.ml_weight * policy.model_confidence)
                + ((1.0 - policy.ml_weight) * policy.heuristic_confidence)
        }
        crate::detector_ml_policy::ActiveMlMode::Authoritative => policy.model_confidence,
    };

    let context_penalty_applies = match policy.code_context {
        context::CodeContext::Comment => !policy.scan_comments,
        context::CodeContext::TestCode | context::CodeContext::Documentation => {
            policy.penalize_test_paths
        }
        _ => false,
    };
    if context_penalty_applies && confidence < 0.95 {
        confidence *= policy.code_context.confidence_multiplier();
    }
    confidence
}

#[cfg(feature = "ml")]
pub(crate) fn ml_pending_match_confidence(
    pending: &crate::types::MlPendingMatch,
    model_confidence: f64,
    scan_comments: bool,
    penalize_test_paths: bool,
) -> f64 {
    ml_pending_confidence(MlConfidencePolicy {
        heuristic_confidence: pending.heuristic_conf,
        model_confidence,
        ml_weight: pending.ml_weight,
        mode: pending.ml_mode,
        code_context: pending.code_context,
        scan_comments,
        penalize_test_paths,
    })
}

#[cfg(feature = "ml")]
#[inline]
pub(crate) fn ml_score_for_candidate_text(text: &str, score: impl FnOnce() -> f64) -> f64 {
    if text.is_empty() {
        0.0
    } else {
        score()
    }
}

#[cfg(all(feature = "ml", feature = "gpu"))]
pub(crate) fn apply_empty_candidate_score_policy<'a>(
    texts: impl IntoIterator<Item = &'a str>,
    scores: &mut [f64],
) {
    for (text, score) in texts.into_iter().zip(scores.iter_mut()) {
        if text.is_empty() {
            *score = 0.0;
        }
    }
}

#[cfg(feature = "ml")]
pub(crate) fn probabilistic_promise_confidence_override(
    credential: &str,
    is_service_detector: bool,
    has_companion: bool,
) -> Option<f64> {
    if crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential) {
        return None;
    }
    // A service regex or matched companion is independent detector-owned
    // evidence. The probabilistic gate may cheaply reject an unaccompanied
    // generic candidate, but it must not bypass ML and manufacture a 0.1 score
    // for either stronger path. Anchor strength is deliberately irrelevant:
    // weak service patterns still prove which detector owns the candidate.
    (!is_service_detector && !has_companion).then_some(0.1)
}

#[cfg(feature = "entropy")]
/// Score an entropy fallback using the active owner's compiled TOML tiers.
pub(crate) fn entropy_fallback_confidence(
    entropy: f64,
    keyword: &str,
    entropy_high: f64,
    entropy_very_high: f64,
) -> f64 {
    // A NaN entropy is undefined evidence, never a real measurement
    // (`shannon_entropy` is bounded to `[0, 8]`). Critically, `f64::min` IGNORES
    // NaN, so the `0.55.min(entropy / 8.0)` fallback below would silently launder
    // a NaN into a 0.55 mid-tier confidence (Law 10: no silent fallback). Collapse
    // NaN to the zero-evidence case up front, loudly in debug so a broken upstream
    // entropy is caught, conservatively (0.0) in release so it can never be
    // credited as signal.
    debug_assert!(
        !entropy.is_nan(),
        "entropy_fallback_confidence received NaN entropy, broken upstream entropy computation"
    );
    let entropy = if entropy.is_nan() { 0.0 } else { entropy };
    // Keyword-free high-entropy candidates carry weaker evidence than
    // keyword/isolated-token candidates, so only the latter get the historical
    // +0.10 lift. The emit path owns routing; this owner owns the base score.
    let base_confidence = if entropy >= entropy_very_high {
        0.75
    } else if entropy >= entropy_high {
        0.65
    } else {
        0.55_f64.min(entropy / 8.0)
    };
    if keyword != crate::entropy::KEYWORD_FREE_LABEL {
        (base_confidence + 0.1).min(0.90_f64)
    } else {
        base_confidence
    }
}

pub(crate) fn generic_secret_confidence(
    context: context::CodeContext,
    scan_comments: bool,
    penalize_test_paths: bool,
    entropy: f64,
    value_len: usize,
) -> f64 {
    // The test/docs base-confidence haircut follows the same operator policy
    // as the later path penalties: `--no-suppress-test-fixtures` clears test
    // and documentation haircuts, while `--scan-comments` promotes comments to
    // the ordinary-source floor. Keep the entropy/length boosts here too so the
    // generic emitter supplies raw signals, not a private confidence formula.
    let base_confidence = match context {
        context::CodeContext::TestCode if penalize_test_paths => 0.25,
        context::CodeContext::Comment if scan_comments => 0.60,
        context::CodeContext::Documentation if penalize_test_paths => 0.30,
        context::CodeContext::Comment => 0.30,
        _ => 0.60,
    };
    let entropy_boost = ((entropy - 3.5) * 0.1).clamp(0.0, 0.25);
    let length_boost = ((value_len as f64 - 16.0) * 0.005).clamp(0.0, 0.15);
    // Lower clamp is defensive: the boosts already floor at 0.0, but pin the
    // whole score into [0.0, 0.95] so no future base/boost retune can emit a
    // negative or >0.95 confidence into the pipeline.
    (base_confidence + entropy_boost + length_boost).clamp(0.0, 0.95)
}
