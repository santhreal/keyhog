use super::{CONFIDENCE_MAX, CONFIDENCE_MIN};

#[derive(serde::Deserialize)]
struct ExamplePathComponents {
    components: Vec<String>,
}

fn parse_fixture_path_components(raw: &str) -> Result<Vec<String>, String> {
    toml::from_str::<ExamplePathComponents>(raw)
        .map(|parsed| parsed.components)
        .map_err(|error| error.to_string())
}

/// Tier-B fixture/example path components that trigger the path-confidence
/// haircut. Loaded from the SAME `rules/example-path-components.toml` the
/// suppression path uses so the two lists cannot drift to different sets (they
/// previously diverged: this owner carried `sample`/`samples` but not
/// `fixture`/`fixtures`, the suppression owner the reverse).
static FIXTURE_PATH_COMPONENTS: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
    match parse_fixture_path_components(include_str!(
        "../../../../rules/example-path-components.toml"
    )) {
        Ok(components) => components,
        Err(error) => panic!(
            "rules/example-path-components.toml is invalid: {error}. \
                 Fix the bundled Tier-B example path components list."
        ),
    }
});

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
pub(crate) fn finalize_confidence(score: f64) -> f64 {
    if score.is_nan() {
        return CONFIDENCE_MIN;
    }
    score.clamp(CONFIDENCE_MIN, CONFIDENCE_MAX)
}

/// Check if a credential contains a known placeholder word (case-insensitive).
///
/// Delegates to the shared Tier-B placeholder-word loader so surface-form,
/// decoded-form, and doc-marker suppression cannot drift.
pub(crate) fn contains_placeholder_word(credential: &str) -> bool {
    crate::placeholder_words::contains_placeholder_word(credential)
}

fn has_credential_url_userinfo_without_placeholder(credential: &str) -> bool {
    let Some(scheme_end) = credential.find("://") else {
        return false;
    };
    if scheme_end == 0
        || !credential[..scheme_end]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
    {
        return false;
    }
    let authority = &credential[scheme_end + 3..];
    let authority_end = authority
        .find(|ch: char| {
            matches!(ch, '/' | '?' | '#' | '"' | '\'' | '<' | '>' | ')' | '(') || ch.is_whitespace()
        })
        .unwrap_or(authority.len()); // LAW10: search/boundary miss => span end (whole remainder), recall-safe boundary default
    let authority = &authority[..authority_end];
    let Some(at) = authority.rfind('@') else {
        return false;
    };
    let userinfo = &authority[..at];
    let Some(colon) = userinfo.find(':') else {
        return false;
    };
    colon + 1 < userinfo.len() && !contains_placeholder_word(userinfo)
}

/// Compute the ratio of unique bytes to total bytes.
pub(crate) fn char_diversity(credential: &str) -> f64 {
    let len = credential.len();
    if len == 0 {
        return 1.0;
    }
    crate::entropy::unique_byte_count(credential.as_bytes()) as f64 / len as f64
}

/// Length of the longest run of identical bytes in `credential`.
///
/// The absolute companion to [`max_repeat_run`] (which is this normalized by
/// length). A long ABSOLUTE run is a degenerate-placeholder signal that a length
/// ratio misses whenever a fixed detector prefix dilutes it: `AKIAXXXXXXXXXXXXXXXX`
/// has a 16-character `X` run but a ratio of only `16/20 = 0.8`. Real
/// base32/hex/base64 secret bodies have a longest natural run of ~2-3.
fn longest_repeat_run_len(credential: &str) -> usize {
    let bytes = credential.as_bytes();
    if bytes.is_empty() {
        return 0;
    }
    let mut max_run = 1usize;
    let mut current_run = 1usize;
    for index in 1..bytes.len() {
        if bytes[index] == bytes[index - 1] {
            current_run += 1;
            if current_run > max_run {
                max_run = current_run;
            }
        } else {
            current_run = 1;
        }
    }
    max_run
}

/// Compute the length of the longest run of identical characters divided by the total length.
pub(crate) fn max_repeat_run(credential: &str) -> f64 {
    let len = credential.len();
    if len == 0 {
        return 0.0;
    }
    longest_repeat_run_len(credential) as f64 / len as f64
}

/// Absolute run length at/above which a credential is a degenerate placeholder
/// regardless of detector class: no real high-entropy secret body carries a run
/// of this many identical characters (probability for a base32/hex/base64 body
/// is vanishing), while synthetic placeholders (`AKIAXXXXXXXXXXXXXXXX`,
/// `key=00000000000000`, `aaaa…`) routinely do. Length-agnostic, so it catches
/// fixed-prefix placeholders whose prefix dilutes [`max_repeat_run`] below the
/// per-class ratio gate.
const DEGENERATE_RUN_LEN: usize = 10;

/// True if `credential` contains a degenerate single-character run (>=
/// [`DEGENERATE_RUN_LEN`] identical bytes), a placeholder/padding artifact no
/// real secret body carries. Single source of truth for the run heuristic:
/// consumed by [`apply_post_ml_penalties`] (both detector classes) AND by
/// `prefixes::known_prefix_confidence_floor` (so a known-prefix placeholder like
/// `AKIAXXXXXXXXXXXXXXXX` is NOT floored back to 0.8 after the penalty crushes
/// it (exactly parallel to the placeholder-word skip)).
pub(crate) fn is_degenerate_repeat(credential: &str) -> bool {
    longest_repeat_run_len(credential) >= DEGENERATE_RUN_LEN
}

/// A detector is "service-anchored" when it is not a generic-* / entropy-* /
/// private-key fallback. Such a detector's own regex (a service-specific
/// keyword + shape) is positive evidence that the matched bytes ARE the
/// credential, so the shape-based suspicion heuristics (probabilistic-promise
/// gate, char-diversity / repeat-run penalties) that exist to filter the
/// anchorless generic path must not bury it. This is the single predicate
/// behind every "named anchor overrides shape" decision; keep it in one place.
pub(crate) fn is_service_anchored_detector(detector_id: &str) -> bool {
    crate::detector_ids::is_service_anchored_detector(detector_id)
}

/// Multiplier applied when a credential literally contains a placeholder word
/// (`EXAMPLE`, `PLACEHOLDER`, …) on its surface or decoded form: it is a doc
/// sample, not a live secret. Single owner for the placeholder-word slam so the
/// surface-form and decoded-form paths cannot drift to different factors.
const PLACEHOLDER_WORD_PENALTY: f64 = 0.05;

/// Multiplier applied when a value's byte alphabet is so small it is effectively
/// one repeated symbol (`char_diversity` below the per-class floor), a padding /
/// placeholder artifact, not a real high-entropy secret body. Shared by the named
/// and generic detector branches (same magnitude, different diversity threshold).
const LOW_DIVERSITY_PENALTY: f64 = 0.1;

/// Multiplier applied when a value's SHAPE is degenerate: a single-character run
/// that is a large fraction of the token or long in absolute terms
/// ([`is_degenerate_repeat`]). No real secret body carries such a run. Shared by
/// the named and generic detector branches.
const DEGENERATE_SHAPE_PENALTY: f64 = 0.1;

/// Multiplier applied when decode-through proves the value is a DATA ENVELOPE,
/// not a credential: it base64/hex-decodes to a binary asset (magic bytes) or a
/// full protobuf message, is a uniform random-base64 blob, or is a double-base64
/// wrapper. Slammed hardest, no service publishes a secret in this shape, so
/// all three data-envelope arms share one factor.
const DATA_ENVELOPE_PENALTY: f64 = 0.02;

/// Apply post-ML penalties based on placeholder, diversity, repetition, and
/// decoded-envelope evidence.
///
/// `is_named` is true for service-anchored detectors. For those, the
/// char-diversity and repeat-run SHAPE penalties are skipped: a 64-char hex
/// Linode PAT or a UUID Heroku key has diversity ≤ 0.25 purely because hex/
/// UUID alphabets are small, NOT because it is a false positive - the service
/// anchor already proved it is real. The placeholder-WORD penalty still
/// applies to everything (a named token literally containing "EXAMPLE" /
/// "placeholder" is a doc sample regardless of which detector fired).
/// Detector-owned canonical hex uses the same narrow exemption for generic
/// findings: exact assignment-key and length evidence replaces the otherwise
/// destructive small-alphabet and decoded-envelope signals, while placeholder
/// and degenerate-repeat penalties remain active.
pub(crate) fn apply_post_ml_penalties_with_encoded_text_lift(
    score: f64,
    credential: &str,
    is_named: bool,
    allow_encoded_text_secret: bool,
    allow_canonical_hex_key: bool,
) -> f64 {
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
    let has_surface_placeholder = contains_placeholder_word(credential);
    let decode_evidence = crate::decode_structure::evidence(credential);
    let has_decoded_placeholder = decode_evidence.decoded_contains_placeholder();
    let placeholder_is_only_url_host = is_named
        && has_surface_placeholder
        && !has_decoded_placeholder
        && has_credential_url_userinfo_without_placeholder(credential);
    if (has_surface_placeholder || has_decoded_placeholder) && !placeholder_is_only_url_host {
        adjusted *= PLACEHOLDER_WORD_PENALTY;
    }
    if is_named {
        // Named detectors: a small-alphabet body (64-char hex has ≤ 16 distinct
        // symbols → diversity ~0.25; base32 tokens similar) is a LEGIT
        // credential, not an FP - the service anchor already proved it. Only
        // penalize DEGENERATE values (effectively one repeated character), which
        // no real key has, so a Linode 64-hex PAT survives but `aaaa…aaaa` dies.
        if char_diversity(credential) < 0.1 {
            adjusted *= LOW_DIVERSITY_PENALTY;
        }
        // Degenerate repeat: a run that is either a large FRACTION of the token
        // (ratio > 0.8) OR long in ABSOLUTE terms (>= DEGENERATE_RUN_LEN). The
        // absolute arm is load-bearing because even the service anchor cannot
        // rescue an all-`X` body: `(?-i)(AKIA|ASIA)[0-9A-Z]{16}` matches
        // `AKIAXXXXXXXXXXXXXXXX`, whose 4-char prefix dilutes the ratio to exactly
        // 0.8 (NOT > 0.8) while its 16-char `X` run is plainly synthetic. One
        // penalty either way (no double-count with the ratio arm).
        if max_repeat_run(credential) > 0.8 || is_degenerate_repeat(credential) {
            adjusted *= DEGENERATE_SHAPE_PENALTY;
        }
    } else {
        if !allow_canonical_hex_key && char_diversity(credential) < 0.3 {
            adjusted *= LOW_DIVERSITY_PENALTY;
        }
        if max_repeat_run(credential) > 0.5 || is_degenerate_repeat(credential) {
            adjusted *= DEGENERATE_SHAPE_PENALTY;
        }
        // Decode-through coherence (generic detectors only). A generic
        // high-entropy candidate that base64/hex-decodes to an identifiable
        // binary asset (PNG/gzip/zip/ELF/PDF/... magic bytes) or a full
        // protobuf-wire message is embedded data, not a credential. These
        // signals are definitional - real secrets carry no magic header and do
        // not parse end-to-end as protobuf - so this never fires on a named
        // detector (skipped here) and effectively never on a real generic
        // secret. This is keyhog's decode-through advantage feeding scoring.
        if !allow_canonical_hex_key && decode_evidence.is_binary_payload() {
            adjusted *= DATA_ENVELOPE_PENALTY;
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
        if !allow_canonical_hex_key
            && !allow_encoded_text_secret
            && crate::decode_structure::looks_like_uniform_base64_blob(credential)
        {
            adjusted *= DATA_ENVELOPE_PENALTY;
        }
        // Double-base64 wrapper (k8s `data:` shape: outer base64 decodes to
        // bytes that are themselves all standard-base64 alphabet, length
        // >= 32). The inner bytes are the user-supplied content; the outer
        // wrapper is categorically a data envelope, not a credential. Mirror
        // v32 had 7 such FPs concentrated in yaml/k8s-secret fixtures.
        if !allow_canonical_hex_key
            && !allow_encoded_text_secret
            && decode_evidence.decoded_is_base64_blob()
        {
            adjusted *= DATA_ENVELOPE_PENALTY;
        }
    }
    finalize_confidence(adjusted)
}

/// Apply the explicitly supplied Bayesian calibration multiplier for
/// `detector_id`.
///
/// The scanner never discovers a calibration cache from disk on its own: a
/// persisted Beta(α, β) store changes confidence and therefore must come from
/// resolved CLI/TOML state. Fresh / uncalibrated detectors return 0.5 (uniform
/// prior) - we don't penalize uncalibrated detectors below 0.5 because the
/// prior is symmetric, so 0.5 × score keeps previous behavior approximately
/// stable until observations accumulate. Detectors with a long clean record
/// (posterior > 0.5) get amplified; chronic FP-emitters get muted.
pub(crate) fn apply_calibration_multiplier(
    score: f64,
    detector_id: &str,
    calibration: Option<&keyhog_core::Calibration>,
) -> f64 {
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
    finalize_confidence(score * counters.posterior_mean())
}

/// Apply path-based confidence penalties for matches in test or placeholder directories.
///
/// `penalize = false` is the scanner side of `--no-suppress-test-fixtures`.
/// The NaN-safety barrier still runs in every branch.
pub(crate) fn apply_path_confidence_penalties(
    score: f64,
    path: Option<&str>,
    penalize: bool,
) -> f64 {
    // Even when there's no path to inspect, the score must still pass
    // through the NaN-safety barrier - a NaN entering this function
    // would otherwise propagate verbatim into the final finding.
    let Some(path) = path else {
        return finalize_confidence(score);
    };
    if !penalize {
        return finalize_confidence(score);
    }
    let is_fixture_like = crate::platform_compat::path_component_matches(path, |component| {
        FIXTURE_PATH_COMPONENTS
            .iter()
            .any(|fixture| component.eq_ignore_ascii_case(fixture))
            || crate::placeholder_words::words()
                .iter()
                .any(|word| component.eq_ignore_ascii_case(word.lower()))
    });

    let adjusted = if is_fixture_like { score * 0.5 } else { score };
    finalize_confidence(adjusted)
}


#[cfg(test)]
#[path = "../../tests/unit/confidence_penalties_inline.rs"]
mod tests;
