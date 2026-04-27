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

/// Apply post-ML penalties based on hard-coded placeholder heuristics.
pub fn apply_post_ml_penalties(score: f64, credential: &str) -> f64 {
    if credential.is_empty() {
        return score;
    }
    let mut adjusted = score;
    if contains_placeholder_word(credential) {
        adjusted *= 0.05;
    }
    if char_diversity(credential) < 0.3 {
        adjusted *= 0.1;
    }
    if max_repeat_run(credential) > 0.5 {
        adjusted *= 0.1;
    }
    adjusted.clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
}

/// Apply the Bayesian calibration multiplier for `detector_id`.
///
/// Reads the persisted Beta(α, β) counters at process startup (lazy via
/// `OnceLock`) and multiplies the score by the posterior mean. Fresh /
/// uncalibrated detectors return 0.5 (uniform prior) — we DON'T penalize
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
        return score;
    };
    // Only apply when the detector has actual observations beyond the
    // Beta(1, 1) prior — otherwise the multiplier is exactly 0.5 and would
    // halve every uncalibrated finding's confidence, which is too
    // aggressive on a fresh install. Once a detector accumulates real
    // history, the multiplier diverges from 0.5 and meaningfully shapes
    // the score.
    let counters = calibration.counters(detector_id);
    if counters.observations() == 0 {
        return score;
    }
    let multiplier = counters.posterior_mean();
    (score * multiplier).clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
}

/// Apply path-based confidence penalties for matches in test, example, or dummy directories.
pub fn apply_path_confidence_penalties(score: f64, path: Option<&str>) -> f64 {
    let Some(path) = path else { return score };
    let lower = path.to_lowercase();
    let mut adjusted = score;

    let is_test_like = lower.split(['/', '\\']).any(|component| {
        matches!(
            component,
            "test" | "tests" | "example" | "examples" | "sample" | "samples" | "dummy"
        )
    });

    if is_test_like {
        adjusted *= 0.5;
    }

    adjusted.clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
}
