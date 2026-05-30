use super::{CONFIDENCE_MAX, CONFIDENCE_MIN};
// Single source of truth for the placeholder-word set. Previously this module
// kept a byte-identical local copy of `decode_structure`'s array (the same six
// lowercase words, the same "NOT included" exclusions); the two drifted apart
// is exactly the duplication this consolidation removes. The surface-form and
// decoded-form placeholder checks now read the one exported const.
use crate::decode_structure::PLACEHOLDER_WORDS;

/// Sanitize a confidence value so a NaN or infinity entering the
/// pipeline can never reach the final finding.
///
/// kimi-confidence audit: `f64::clamp` does NOT sanitize NaN - calling
/// `f64::NAN.clamp(0.0, 1.0)` returns NaN. The GPU-backed ML scorer
/// reads raw f32 from a staging buffer and casts to f64 without range
/// validation; a driver bug, shader miscompile, or adversarial weights
/// buffer can therefore produce NaN/Inf scores that propagate through
/// every `score *= multiplier; score.clamp(0.0, 1.0)` chain and end
/// up serialized into the SARIF output as `confidence: NaN`.
///
/// Treat NaN as the "no signal" sentinel - return the minimum confidence
/// (which is what the heuristic-only path would have produced if ML had
/// returned `None`). Treat +/-Inf the same way the original clamp would
/// have, since clamp handles infinities correctly.
#[inline]
pub fn finalize_confidence(score: f64) -> f64 {
    if score.is_nan() {
        return CONFIDENCE_MIN;
    }
    score.clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
}

/// Check if a credential contains a known placeholder word (case-insensitive).
///
/// Delegates to the crate's canonical SIMD-skimming substring search
/// (`ascii_ci::ci_find`, a `memchr2` first-byte skim) instead of the naive
/// `windows().any(eq_ignore_ascii_case)` scan this module used to re-implement.
/// Every entry of `PLACEHOLDER_WORDS` is an ASCII-lowercase byte literal, which
/// is exactly `ci_find`'s "needle already lowercase" contract, so no per-call
/// lowering is needed and the hot path pays one `memchr2` skim per word.
pub fn contains_placeholder_word(credential: &str) -> bool {
    let haystack = credential.as_bytes();
    PLACEHOLDER_WORDS
        .iter()
        .any(|word| crate::ascii_ci::ci_find(haystack, word))
}

/// Compute the ratio of unique bytes to total bytes.
pub fn char_diversity(credential: &str) -> f64 {
    let len = credential.len();
    if len == 0 {
        return 1.0;
    }
    let mut seen = [false; 256];
    let mut unique = 0usize;
    for &byte in credential.as_bytes() {
        let slot = &mut seen[byte as usize];
        if !*slot {
            *slot = true;
            unique += 1;
        }
    }
    unique as f64 / len as f64
}

/// Compute the length of the longest run of identical characters divided by the total length.
pub fn max_repeat_run(credential: &str) -> f64 {
    let bytes = credential.as_bytes();
    let len = bytes.len();
    if len == 0 {
        return 0.0;
    }
    let mut max_run = 1usize;
    let mut current_run = 1usize;
    for index in 1..len {
        if bytes[index] == bytes[index - 1] {
            current_run += 1;
            if current_run > max_run {
                max_run = current_run;
            }
        } else {
            current_run = 1;
        }
    }
    max_run as f64 / len as f64
}

/// A detector is "service-anchored" when it is not a generic-* / entropy-* /
/// private-key fallback. Such a detector's own regex (a service-specific
/// keyword + shape) is positive evidence that the matched bytes ARE the
/// credential, so the shape-based suspicion heuristics (probabilistic-promise
/// gate, char-diversity / repeat-run penalties) that exist to filter the
/// anchorless generic path must not bury it. This is the single predicate
/// behind every "named anchor overrides shape" decision; keep it in one place.
pub(crate) fn is_service_anchored_detector(detector_id: &str) -> bool {
    !detector_id.starts_with("generic-")
        && !detector_id.starts_with("entropy-")
        && detector_id != "private-key"
}

/// Apply post-ML penalties based on hard-coded placeholder heuristics.
///
/// `is_named` is true for service-anchored detectors. For those, the
/// char-diversity and repeat-run SHAPE penalties are skipped: a 64-char hex
/// Linode PAT or a UUID Heroku key has diversity ≤ 0.25 purely because hex/
/// UUID alphabets are small, NOT because it is a false positive - the service
/// anchor already proved it is real. The placeholder-WORD penalty still
/// applies to everything (a named token literally containing "EXAMPLE" /
/// "placeholder" is a doc sample regardless of which detector fired).
pub fn apply_post_ml_penalties(score: f64, credential: &str, is_named: bool) -> f64 {
    if credential.is_empty() {
        return score;
    }
    let mut adjusted = score;
    // Placeholder check on both the surface form AND the decoded form:
    // a docs sample that arrives base64-wrapped (e.g.
    // QUtJQUVYQU1QTEVFWEFNUExFMTI= = AKIAEXAMPLEEXAMPLE12) is still a
    // sample. The decode-through composition closes the 9 residual
    // docs-example-marker FPs on the SecretBench mirror that the
    // surface-form check missed.
    if contains_placeholder_word(credential)
        || crate::decode_structure::decoded_contains_placeholder(credential)
    {
        adjusted *= 0.05;
    }
    if is_named {
        // Named detectors: a small-alphabet body (64-char hex has ≤ 16 distinct
        // symbols → diversity ~0.25; base32 tokens similar) is a LEGIT
        // credential, not an FP - the service anchor already proved it. Only
        // penalize DEGENERATE values (effectively one repeated character), which
        // no real key has, so a Linode 64-hex PAT survives but `aaaa…aaaa` dies.
        if char_diversity(credential) < 0.1 {
            adjusted *= 0.1;
        }
        if max_repeat_run(credential) > 0.8 {
            adjusted *= 0.1;
        }
    } else {
        if char_diversity(credential) < 0.3 {
            adjusted *= 0.1;
        }
        if max_repeat_run(credential) > 0.5 {
            adjusted *= 0.1;
        }
        // Decode-through coherence (generic detectors only). A generic
        // high-entropy candidate that base64/hex-decodes to an identifiable
        // binary asset (PNG/gzip/zip/ELF/PDF/... magic bytes) or a full
        // protobuf-wire message is embedded data, not a credential. These
        // signals are definitional - real secrets carry no magic header and do
        // not parse end-to-end as protobuf - so this never fires on a named
        // detector (skipped here) and effectively never on a real generic
        // secret. This is keyhog's decode-through advantage feeding scoring.
        if crate::decode_structure::is_encoded_binary(credential) {
            adjusted *= 0.02;
        }
        // Uniform random-base64 blob (44+ chars, all-base64 alphabet, with
        // `+`/`/`, padding, or high alphabet diversity). The alphabet check
        // clears every well-known service-anchored shape (AWS, GitHub,
        // Stripe, npm, Slack, JWT) so this fires only on the unanchored-
        // random-base64 class - the SecretBench mirror v27 had 56
        // base64-protobuf FPs all matching this shape via generic-secret /
        // generic-password, and v32 had 52 still surviving. Slammed hard
        // (×0.02 like decode_structure) because there is no legitimate
        // service that publishes a 44+ char raw-base64 secret WITHOUT a
        // service-specific prefix; if it has one, a named detector would
        // have matched it instead of generic-*.
        if crate::decode_structure::looks_like_uniform_base64_blob(credential) {
            adjusted *= 0.02;
        }
        // Double-base64 wrapper (k8s `data:` shape: outer base64 decodes to
        // bytes that are themselves all standard-base64 alphabet, length
        // >= 32). The inner bytes are the user-supplied content; the outer
        // wrapper is categorically a data envelope, not a credential. Mirror
        // v32 had 7 such FPs concentrated in yaml/k8s-secret fixtures.
        if crate::decode_structure::decoded_is_base64_blob(credential) {
            adjusted *= 0.02;
        }
    }
    finalize_confidence(adjusted)
}

/// Apply the Bayesian calibration multiplier for `detector_id`.
///
/// Reads the persisted Beta(α, β) counters at process startup (lazy via
/// `OnceLock`) and multiplies the score by the posterior mean. Fresh /
/// uncalibrated detectors return 0.5 (uniform prior) - we DON'T penalize
/// uncalibrated detectors below 0.5 because the prior is symmetric, so
/// 0.5 × score keeps the previous behavior approximately stable until
/// observations accumulate. Detectors with a long clean record (posterior
/// > 0.5) get amplified; chronic FP-emitters get muted.
///
/// Tier-B moat innovation #4 (live integration). The data layer +
/// `keyhog calibrate` CLI ship the counters; this function pipes the
/// value into the actual scoring path.
///
/// Bypass when no calibration cache exists: returns `score` unchanged so
/// the scanner stays usable on a fresh install.
pub fn apply_calibration_multiplier(score: f64, detector_id: &str) -> f64 {
    use keyhog_core::calibration::Calibration;
    use std::sync::OnceLock;
    static CALIBRATION: OnceLock<Option<Calibration>> = OnceLock::new();
    let calibration = CALIBRATION.get_or_init(|| {
        let path = keyhog_core::calibration::default_cache_path()?;
        if !path.exists() {
            return None;
        }
        Some(Calibration::load(&path))
    });
    let Some(calibration) = calibration else {
        // Even the bypass path runs through finalize_confidence so a
        // NaN entering this function (from an upstream GPU leak)
        // doesn't propagate verbatim to the final finding.
        return finalize_confidence(score);
    };
    // Only apply when the detector has actual observations beyond the
    // Beta(1, 1) prior - otherwise the multiplier is exactly 0.5 and would
    // halve every uncalibrated finding's confidence, which is too
    // aggressive on a fresh install. Once a detector accumulates real
    // history, the multiplier diverges from 0.5 and meaningfully shapes
    // the score.
    let counters = calibration.counters(detector_id);
    if counters.observations() == 0 {
        return finalize_confidence(score);
    }
    let multiplier = counters.posterior_mean();
    finalize_confidence(score * multiplier)
}

/// Apply path-based confidence penalties for matches in test, example, or dummy directories.
pub fn apply_path_confidence_penalties(score: f64, path: Option<&str>) -> f64 {
    // Even when there's no path to inspect, the score must still pass
    // through the NaN-safety barrier - a NaN entering this function
    // would otherwise propagate verbatim into the final finding.
    let Some(path) = path else {
        return finalize_confidence(score);
    };
    // Per-segment ASCII-case-insensitive compare - no full-path
    // lowercase allocation per match.
    let is_test_like = path.split(['/', '\\']).any(|component| {
        component.eq_ignore_ascii_case("test")
            || component.eq_ignore_ascii_case("tests")
            || component.eq_ignore_ascii_case("example")
            || component.eq_ignore_ascii_case("examples")
            || component.eq_ignore_ascii_case("sample")
            || component.eq_ignore_ascii_case("samples")
            || component.eq_ignore_ascii_case("dummy")
    });

    let adjusted = if is_test_like { score * 0.5 } else { score };
    finalize_confidence(adjusted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    // Round 1 FP-killer: base64-protobuf cause #6. Generic-secret matches on
    // base64-of-base64 (k8s `data:` outer wrapper) must be slammed by the
    // post-ML penalty so the 7 yaml/k8s-secret FPs collapse.
    #[test]
    fn apply_post_ml_penalties_slams_double_base64_for_generic() {
        // 40-char inner (high-diversity base64 alphabet, distinct >= 32 so
        // it survives the alphabet-diversity check). Outer decodes to
        // inner which is all base64 alphabet, length 40.
        let inner = "NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1J";
        let outer = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let pre = 0.9_f64;
        let post = apply_post_ml_penalties(pre, &outer, false);
        assert!(
            post <= pre * 0.05,
            "generic-* finding whose value is base64-of-base64 must be \
             slammed by the post-ML penalty (got {post} from {pre})",
        );
    }

    // Negative twin: a named (service-anchored) detector match with the same
    // wrapper shape must NOT be slammed - the named anchor already proved
    // the bytes are credential content. is_named=true skips the decode-
    // through gates entirely. Inner has high diversity so the named
    // char_diversity penalty (< 0.1) does not fire either.
    #[test]
    fn apply_post_ml_penalties_preserves_named_double_base64() {
        let inner = "NbrnTP3fAbnFbmOHnKYaXRvj7uff0LYTH8xIZM1J";
        let outer = base64::engine::general_purpose::STANDARD.encode(inner.as_bytes());
        let pre = 0.9_f64;
        let post = apply_post_ml_penalties(pre, &outer, true);
        assert!(
            post >= pre - 1e-9,
            "named-detector match with base64-of-base64 shape must NOT be \
             slammed (named anchor overrides shape gates); got {post} \
             from {pre}",
        );
    }
}
