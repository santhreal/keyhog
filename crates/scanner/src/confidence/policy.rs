use crate::context;

pub(crate) type CredentialChecksumPolicy = crate::checksum::ChecksumConfidenceDecision;

#[inline]
pub(crate) fn checksum_policy_for(credential: &str) -> CredentialChecksumPolicy {
    crate::checksum::ChecksumConfidenceDecision::for_credential(credential)
}

#[inline]
pub(crate) fn apply_checksum_confidence(confidence: f64, credential: &str) -> Option<f64> {
    checksum_policy_for(credential).adjusted_confidence(confidence)
}

pub(crate) struct ReportConfidencePolicy<'a> {
    pub(crate) credential: &'a str,
    pub(crate) detector_id: &'a str,
    pub(crate) file_path: Option<&'a str>,
    pub(crate) is_named_detector: bool,
    pub(crate) penalize_test_paths: bool,
    pub(crate) allow_encoded_text_lift: bool,
    pub(crate) calibration: Option<&'a keyhog_core::Calibration>,
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
    );
    let confidence = crate::confidence::apply_path_confidence_penalties(
        confidence,
        policy.file_path,
        policy.penalize_test_paths,
    );
    let confidence =
        if let Some(floor) = crate::confidence::known_prefix_confidence_floor(policy.credential) {
            confidence.max(floor)
        } else {
            confidence
        };
    let confidence = crate::confidence::apply_calibration_multiplier(
        confidence,
        policy.detector_id,
        policy.calibration,
    );
    apply_checksum_confidence(confidence, policy.credential)
}

#[cfg(feature = "ml")]
#[derive(Clone, Copy)]
pub(crate) struct MlConfidencePolicy {
    pub(crate) heuristic_confidence: f64,
    pub(crate) model_confidence: f64,
    pub(crate) ml_weight: f64,
    pub(crate) model_authoritative: bool,
    pub(crate) code_context: context::CodeContext,
    pub(crate) scan_comments: bool,
    pub(crate) penalize_test_paths: bool,
}

#[cfg(feature = "ml")]
pub(crate) fn ml_pending_confidence(policy: MlConfidencePolicy) -> f64 {
    let mut confidence = if policy.model_authoritative {
        policy.model_confidence
    } else {
        let blended = (policy.ml_weight * policy.model_confidence)
            + ((1.0 - policy.ml_weight) * policy.heuristic_confidence);
        blended
            .max(policy.heuristic_confidence)
            .max(policy.model_confidence)
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
pub(crate) fn probabilistic_promise_confidence_override(
    credential: &str,
    is_named_detector: bool,
) -> Option<f64> {
    if crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential) {
        return None;
    }
    let identifier_shaped =
        crate::suppression::shape::looks_like_word_separated_identifier(credential)
            || crate::suppression::shape::looks_like_pure_identifier(credential);
    (!is_named_detector || identifier_shaped).then_some(0.1)
}

#[cfg(feature = "simdsieve")]
pub(crate) fn hot_pattern_confidence(
    credential: &str,
    detector_id: &str,
    file_path: Option<&str>,
    penalize_test_paths: bool,
    calibration: Option<&keyhog_core::Calibration>,
) -> Option<f64> {
    const BASE_CONFIDENCE: f64 = 0.7;
    finalize_report_confidence(
        BASE_CONFIDENCE,
        ReportConfidencePolicy {
            credential,
            detector_id,
            file_path,
            is_named_detector: true,
            penalize_test_paths,
            allow_encoded_text_lift: false,
            calibration,
        },
    )
}

#[cfg(feature = "entropy")]
pub(crate) fn entropy_fallback_confidence(entropy: f64, keyword: &str) -> f64 {
    // Keyword-free high-entropy candidates carry weaker evidence than
    // keyword/isolated-token candidates, so only the latter get the historical
    // +0.10 lift. The emit path owns routing; this owner owns the base score.
    let base_confidence = if entropy >= crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD {
        0.75
    } else if entropy >= crate::entropy::HIGH_ENTROPY_THRESHOLD {
        0.65
    } else {
        0.55_f64.min(entropy / 8.0)
    };
    if keyword != "none (high-entropy)" {
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
    let entropy_boost = ((entropy - 3.5) * 0.1).min(0.25);
    let length_boost = ((value_len as f64 - 16.0) * 0.005).clamp(0.0, 0.15);
    (base_confidence + entropy_boost + length_boost).min(0.95)
}
