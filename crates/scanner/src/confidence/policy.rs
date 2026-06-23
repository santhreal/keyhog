use crate::context;

pub(crate) enum MlScoreResult<'a> {
    /// Score is final and the match can be pushed immediately.
    Final(f64),
    #[cfg(feature = "ml")]
    /// ML scoring is batched at the end of the scan.
    Pending {
        heuristic_conf: f64,
        code_context: crate::context::CodeContext,
        credential: std::borrow::Cow<'a, str>,
        ml_context: std::borrow::Cow<'a, str>,
    },
    /// Zero-sized placeholder that keeps the `'a` lifetime live when ML batch
    /// scoring is compiled out (lean / `--no-default-features` build). Never
    /// constructed - it exists solely so the type still carries `'a` without
    /// the `ml` feature, where only the borrowing `Pending` variant uses it.
    #[cfg(not(feature = "ml"))]
    #[doc(hidden)]
    _Lifetime(std::marker::PhantomData<&'a ()>),
}

pub(crate) type CredentialChecksumPolicy = crate::checksum::ChecksumConfidenceDecision;

#[inline]
pub(crate) fn checksum_policy_for(credential: &str) -> CredentialChecksumPolicy {
    crate::checksum::ChecksumConfidenceDecision::for_credential(credential)
}

#[inline]
pub(crate) fn apply_checksum_confidence(confidence: f64, credential: &str) -> Option<f64> {
    checksum_policy_for(credential).adjusted_confidence(confidence)
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
    pub(crate) keyword_nearby: bool,
    pub(crate) sensitive_file: bool,
    pub(crate) match_length: usize,
    pub(crate) has_companion: bool,
    pub(crate) code_context: context::CodeContext,
    pub(crate) penalize_test_paths: bool,
    pub(crate) ml_enabled: bool,
    pub(crate) credential: &'a str,
    pub(crate) is_named_detector: bool,
    #[cfg(feature = "ml")]
    pub(crate) data: &'a str,
    #[cfg(feature = "ml")]
    pub(crate) line: usize,
    #[cfg(feature = "ml")]
    pub(crate) file_path: Option<&'a str>,
    #[cfg(feature = "ml")]
    pub(crate) ml_context_radius_lines: usize,
}

pub(crate) fn match_heuristic_confidence(policy: MatchHeuristicConfidencePolicy) -> f64 {
    let raw_confidence =
        crate::confidence::compute_confidence(&crate::confidence::ConfidenceSignals {
            has_literal_prefix: policy.has_literal_prefix,
            has_context_anchor: policy.has_context_anchor,
            entropy: policy.entropy,
            keyword_nearby: policy.keyword_nearby,
            sensitive_file: policy.sensitive_file,
            match_length: policy.match_length,
            has_companion: policy.has_companion,
        });
    pre_ml_heuristic_confidence(
        raw_confidence,
        policy.code_context,
        policy.penalize_test_paths,
    )
}

pub(crate) fn candidate_match_score<'a>(
    policy: CandidateMatchScorePolicy<'a>,
) -> Option<MlScoreResult<'a>> {
    let heuristic_conf = match_heuristic_confidence(MatchHeuristicConfidencePolicy {
        has_literal_prefix: policy.has_literal_prefix,
        has_context_anchor: policy.has_context_anchor,
        entropy: policy.entropy,
        keyword_nearby: policy.keyword_nearby,
        sensitive_file: policy.sensitive_file,
        match_length: policy.match_length,
        has_companion: policy.has_companion,
        code_context: policy.code_context,
        penalize_test_paths: policy.penalize_test_paths,
    });

    #[cfg(not(feature = "ml"))]
    let score_result = {
        let _ = (policy.ml_enabled, policy.is_named_detector);
        MlScoreResult::Final(heuristic_conf)
    };

    #[cfg(feature = "ml")]
    let score_result = {
        if !policy.ml_enabled {
            MlScoreResult::Final(heuristic_conf)
        } else if let Some(confidence) =
            probabilistic_promise_confidence_override(policy.credential, policy.is_named_detector)
        {
            MlScoreResult::Final(confidence)
        } else {
            let text_context = crate::pipeline::local_context_window(
                policy.data,
                policy.line,
                policy.ml_context_radius_lines,
            );
            let ml_context = match policy.file_path {
                Some(path) => format!("file:{path}\n{text_context}"),
                None => text_context.to_string(),
            };

            MlScoreResult::Pending {
                heuristic_conf,
                code_context: policy.code_context,
                credential: std::borrow::Cow::Borrowed(policy.credential),
                ml_context: std::borrow::Cow::Owned(ml_context),
            }
        }
    };

    match score_result {
        MlScoreResult::Final(confidence) => Some(MlScoreResult::Final(apply_known_prefix_floor(
            confidence,
            policy.credential,
        ))),
        #[cfg(feature = "ml")]
        MlScoreResult::Pending { .. } => Some(score_result),
        #[cfg(not(feature = "ml"))]
        MlScoreResult::_Lifetime(_) => {
            unreachable!("_Lifetime is a never-constructed placeholder variant")
        }
    }
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
    let confidence = apply_known_prefix_floor(confidence, policy.credential);
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
