//! Confidence scoring: combines multiple signals into a 0.0–1.0 score.
//! Higher confidence means more likely to be a real secret.

pub(crate) mod penalties;
pub(crate) mod policy;
mod prefixes;
mod signals;

pub use prefixes::KNOWN_PREFIXES;
pub(crate) use prefixes::{known_prefix_body, known_prefix_confidence_floor};
pub(crate) use signals::ConfidenceSignals;

use crate::entropy::{HIGH_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD};
pub(crate) use penalties::apply_calibration_multiplier;
pub(crate) use penalties::apply_path_confidence_penalties;
pub(crate) use penalties::apply_post_ml_penalties_with_encoded_text_lift;
#[cfg(feature = "entropy")]
pub(crate) use penalties::contains_placeholder_word;
pub(crate) use penalties::is_service_anchored_detector;
pub(crate) use signals::is_sensitive_path;

const SCORE_ZERO: f64 = 0.0;
const CONFIDENCE_MIN: f64 = 0.0;
const CONFIDENCE_MAX: f64 = 1.0;
const LITERAL_PREFIX_WEIGHT: f64 = 0.35;
const CONTEXT_ANCHOR_WEIGHT: f64 = 0.20;
const ENTROPY_WEIGHT: f64 = 0.20;
const HIGH_ENTROPY_PARTIAL_WEIGHT: f64 = 0.12;
/// Confidence-scoring "moderate entropy" tier: at/above this Shannon entropy a
/// finding earns [`MODERATE_ENTROPY_WEIGHT`]. Its `3.0` value coincides with the
/// entropy *detection* floor [`crate::entropy::LOW_ENTROPY_THRESHOLD`] but is a
/// deliberately independent scoring knob (same rationale as
/// [`LOW_ENTROPY_PENALTY_FLOOR`] below), retuning the detection floor must NOT
/// silently drag this scoring tier with it, so it stays a named local owner.
const MODERATE_ENTROPY_THRESHOLD: f64 = 3.0;
const MODERATE_ENTROPY_WEIGHT: f64 = 0.05;
/// Confidence-scoring floor: below this Shannon entropy (with a long-enough
/// match) the finding's confidence is penalized. This is the CONFIDENCE penalty
/// floor and is deliberately distinct from the entropy *detection* floor
/// [`crate::entropy::LOW_ENTROPY_THRESHOLD`] (3.0), different concept, so it
/// carries a different name to keep the ONE-PLACE contract (no two same-named
/// thresholds with different values).
const LOW_ENTROPY_PENALTY_FLOOR: f64 = 2.0;
const LOW_ENTROPY_MIN_MATCH_LENGTH: usize = 10;
const LOW_ENTROPY_PENALTY: f64 = 0.6;
const KEYWORD_NEARBY_WEIGHT: f64 = 0.10;
const SENSITIVE_FILE_WEIGHT: f64 = 0.10;
const COMPANION_WEIGHT: f64 = 0.05;
/// Gap between the configurable entropy floor (the "high" scoring tier,
/// default [`HIGH_ENTROPY_THRESHOLD`] = 4.5) and the "very high" tier that
/// earns the full [`ENTROPY_WEIGHT`]. Derived so the default floor reproduces
/// the canonical [`VERY_HIGH_ENTROPY_THRESHOLD`] (5.8) exactly, while a tuned
/// `--entropy-threshold` / `.keyhog.toml entropy_threshold` slides both tiers
/// together instead of leaving the named-detector scorer pinned to a hardcoded
/// floor the config cannot move.
const VERY_HIGH_ENTROPY_MARGIN: f64 = VERY_HIGH_ENTROPY_THRESHOLD - HIGH_ENTROPY_THRESHOLD;

/// Sum of every earnable signal weight, the denominator that normalizes the
/// weighted signal sum into `0.0..=1.0`. Computed once at compile time from the
/// weight constants above (ONE place to tune weights), replacing the per-call
/// accumulation the scorer previously ran on the hot path. Only [`ENTROPY_WEIGHT`]
/// (the maximum entropy contribution) participates; the partial/moderate entropy
/// tiers are mutually exclusive sub-cases of it.
const MAX_POSSIBLE_SCORE: f64 = LITERAL_PREFIX_WEIGHT
    + CONTEXT_ANCHOR_WEIGHT
    + ENTROPY_WEIGHT
    + KEYWORD_NEARBY_WEIGHT
    + SENSITIVE_FILE_WEIGHT
    + COMPANION_WEIGHT;
const _: () = assert!(MAX_POSSIBLE_SCORE > 0.0);

/// Compute a confidence score from `0.0` to `1.0` using the default,
/// compiled-in entropy floor ([`HIGH_ENTROPY_THRESHOLD`]).
///
/// Prefer [`compute_confidence_with_threshold`] on the named-detector hot
/// path so the resolved `ScannerConfig.entropy_threshold` drives the scoring
/// floor; this wrapper exists for callers that have no config in scope.
pub(crate) fn compute_confidence(signals: &ConfidenceSignals) -> f64 {
    compute_confidence_with_threshold(signals, HIGH_ENTROPY_THRESHOLD)
}

/// Compute a confidence score from `0.0` to `1.0`, anchoring the entropy
/// scoring tiers to the resolved `entropy_threshold` (the same knob honored by
/// the generic entropy path) rather than a hardcoded const. The "high"
/// tier fires at `entropy_threshold`; the "very high" tier (full
/// [`ENTROPY_WEIGHT`]) fires at `entropy_threshold + VERY_HIGH_ENTROPY_MARGIN`.
pub(crate) fn compute_confidence_with_threshold(
    signals: &ConfidenceSignals,
    entropy_threshold: f64,
) -> f64 {
    let mut score = SCORE_ZERO;

    if signals.has_literal_prefix {
        score += LITERAL_PREFIX_WEIGHT;
    }

    if signals.has_context_anchor {
        score += CONTEXT_ANCHOR_WEIGHT;
    }

    let high_entropy_tier = entropy_threshold;
    let very_high_entropy_tier = entropy_threshold + VERY_HIGH_ENTROPY_MARGIN;
    if signals.entropy >= very_high_entropy_tier {
        score += ENTROPY_WEIGHT;
    } else if signals.entropy >= high_entropy_tier {
        score += HIGH_ENTROPY_PARTIAL_WEIGHT;
    } else if signals.entropy >= MODERATE_ENTROPY_THRESHOLD {
        score += MODERATE_ENTROPY_WEIGHT;
    }
    let low_entropy_penalty = if signals.entropy < LOW_ENTROPY_PENALTY_FLOOR
        && signals.match_length > LOW_ENTROPY_MIN_MATCH_LENGTH
    {
        LOW_ENTROPY_PENALTY
    } else {
        CONFIDENCE_MAX
    };

    if signals.keyword_nearby {
        score += KEYWORD_NEARBY_WEIGHT;
    }

    if signals.sensitive_file {
        score += SENSITIVE_FILE_WEIGHT;
    }

    if signals.has_companion {
        score += COMPANION_WEIGHT;
    }

    let normalized_score = (score / MAX_POSSIBLE_SCORE) * low_entropy_penalty;
    normalized_score.clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
}
