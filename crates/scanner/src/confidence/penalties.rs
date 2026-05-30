const PLACEHOLDER_WORDS: &[&[u8]] = &[
    b"example",
    b"dummy",
    b"fake",
    b"sample",
    b"placeholder",
    b"changeme",
    // NOT included: "test" (appears in sk_test_ which is a real Stripe test key),
    // "password" (appears in connection strings like redis://user:password@host),
    // "admin"/"root" (legitimate credentials, not placeholders),
    // "qwerty" (weak but real password, not a placeholder)
];

use super::{CONFIDENCE_MAX, CONFIDENCE_MIN};

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
pub fn contains_placeholder_word(credential: &str) -> bool {
    PLACEHOLDER_WORDS
        .iter()
        .any(|word| contains_ascii_case_insensitive(credential, word))
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
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
        // Token-rarity / BPE-efficiency gate intentionally NOT wired here
        // yet. See `confidence::signals::bigram_uniqueness` for the proxy
        // implementation + the empirical reason the proxy alone isn't safe:
        // a real `ghp_1234567890abcdef1234567890abcdef1234` token scores
        // 0.51 (repeating digit + hex bigrams) while a plain English
        // sentence scores 0.84+. Wiring it would create FNs on real
        // tokens. The accurate version needs the cl100k_base BPE merge
        // table; tracked as task #116. The signal is exported so a future
        // ML re-train can fold it in as feature #42+ once we can afford
        // the ~1.6 MB vocab embedding (or wire a thin remote tokenizer).
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
        // Uniform random-base64 blob (60+ chars, all-base64 alphabet, has
        // `+`/`/` or padding). The 60-char floor + `+`/`/` requirement clears
        // every well-known service-anchored shape (AWS, GitHub, Stripe, npm,
        // Slack, JWT) so this fires only on the unanchored-random-base64
        // class - the SecretBench mirror v27 had 56 base64-protobuf FPs all
        // matching this shape via generic-secret / generic-password. Slammed
        // hard (×0.02 like decode_structure) because there is no legitimate
        // service that publishes a 60+ char raw-base64 secret WITHOUT a
        // service-specific prefix; if it has one, a named detector would have
        // matched it instead of generic-*.
        if crate::decode_structure::looks_like_uniform_base64_blob(credential) {
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
