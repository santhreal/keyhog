use super::isolated::{collect_isolated_bare_candidates_inner, isolated_bare_keyword_context};
#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) use super::isolated::{
    colon_separated_opaque_candidate, lower_dash_app_password_floor_met,
    mixed_contiguous_token_floor_met, mixed_separator_token_floor_met,
    symbolic_alpha_only_opaque_candidate, symbolic_isolated_bare_candidate,
};
#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) use super::isolated::{
    has_isolated_bare_secret_candidate, has_isolated_bare_secret_candidate_with_lines,
};
use super::{
    keywords::*, shannon_entropy, EntropyMatch, FIRST_SOURCE_LINE_NUMBER, HIGH_ENTROPY_THRESHOLD,
    KEYWORD_FREE_MIN_LEN, LOW_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD,
};
use keyhog_core::DetectorSpec;

/// Borrowed view of the detector corpus that actually compiled for this scan.
/// Production phase-2 paths pass this view so custom detector directories and
/// operator-composed specs remain authoritative. Stable public convenience
/// APIs pass `None` and retain the embedded-corpus defaults they historically
/// exposed.
#[derive(Clone, Copy)]
pub(crate) struct ActiveDetectorPolicy<'a> {
    detectors: &'a [DetectorSpec],
    index: &'a crate::generic_keyword_owner::GenericOwningDetectorIndex,
}

impl<'a> ActiveDetectorPolicy<'a> {
    pub(crate) fn new(
        detectors: &'a [DetectorSpec],
        index: &'a crate::generic_keyword_owner::GenericOwningDetectorIndex,
    ) -> Self {
        Self { detectors, index }
    }

    fn spec(self, detector_id: &str) -> Option<&'a DetectorSpec> {
        self.index
            .index_for_id(detector_id)
            .and_then(|index| self.detectors.get(index))
    }
}

fn get_spec<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    detector_id: &str,
) -> Option<&'a DetectorSpec> {
    match active_policy {
        Some(policy) => policy.spec(detector_id),
        None => keyhog_core::detector_spec_by_id(detector_id),
    }
}

pub(crate) fn classify_keyword_to_detector_id(keyword: &str) -> &'static str {
    use crate::ascii_ci::ci_find;
    use crate::detector_ids::{
        GENERIC_API_KEY, GENERIC_KEYWORD_SECRET, GENERIC_PASSWORD, GENERIC_SECRET,
    };
    let bytes = keyword.as_bytes();
    if keyword == KEYWORD_FREE_LABEL {
        GENERIC_SECRET
    } else if crate::entropy::keywords::keyword_is_password_family(keyword) {
        GENERIC_PASSWORD
    } else if ci_find(bytes, b"token") {
        GENERIC_KEYWORD_SECRET
    } else {
        GENERIC_API_KEY
    }
}
use crate::adjudicate::{EntropyShapeStage, StageId};
use crate::entropy::plausibility::{is_secret_plausible, PlausibilityContext};

pub(crate) const CREDENTIAL_CONTEXT_MIN_LEN: usize = 8;
pub(crate) const KEYWORD_FREE_LABEL: &str = "none (high-entropy)";

/// Test-only constructor for a credential-anchor [`KeywordContext`] using the
/// production tuning constants (the low-entropy floor and the credential-context
/// minimum length). Exposed (doc-hidden, via `testing::entropy_scanner`) so the
/// canonical-shape tests in `tests/unit/inline_migrated/` can build the same
/// context the scanner uses, without leaking the private length constant.
#[doc(hidden)]
pub(crate) fn credential_keyword_context(keyword: &str) -> KeywordContext {
    credential_keyword_context_with_lift(keyword, false)
}

/// Lift-aware sibling of [`credential_keyword_context`]: builds the same
/// production credential anchor but with `allow_canonical_shapes` set to
/// `allow_canonical_lift`. Exposed (doc-hidden, via `testing::entropy_scanner`)
/// so the CredData recall-lane unit tests can drive `candidate_is_plausible`
/// through both the strict gate and the model-arbitrated lift.
#[doc(hidden)]
pub(crate) fn credential_keyword_context_with_lift(
    keyword: &str,
    allow_canonical_lift: bool,
) -> KeywordContext {
    let detector_id = classify_keyword_to_detector_id(keyword);
    let spec = get_spec(None, detector_id);
    let entropy_low = spec
        .and_then(|s| s.entropy_low)
        .map_or(LOW_ENTROPY_THRESHOLD, |threshold| threshold);
    let min_len = spec
        .and_then(|s| s.min_len)
        .map_or(CREDENTIAL_CONTEXT_MIN_LEN, |min_len| min_len);
    KeywordContext {
        keyword: keyword.to_string(),
        threshold: entropy_low,
        min_len,
        is_credential_context: true,
        allow_canonical_shapes: allow_canonical_lift,
    }
}

/// Find secret-like tokens using entropy heuristics near likely credential context.
pub fn find_entropy_secrets(
    text: &str,
    min_length: usize,
    context_lines: usize,
    entropy_threshold: f64,
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
) -> Vec<EntropyMatch> {
    let spec = get_spec(None, crate::detector_ids::GENERIC_SECRET);
    let entropy_very_high = spec
        .and_then(|s| s.entropy_very_high)
        .map_or(VERY_HIGH_ENTROPY_THRESHOLD, |threshold| threshold);
    find_entropy_secrets_with_threshold(
        text,
        min_length,
        context_lines,
        entropy_threshold,
        entropy_very_high,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
        None,
    )
}

/// Find entropy-based matches with an explicit keyword-free threshold override.
pub fn find_entropy_secrets_with_threshold(
    text: &str,
    min_length: usize,
    context_lines: usize,
    entropy_threshold: f64,
    keyword_free_threshold: f64,
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
    skip_lines: Option<&std::collections::HashSet<usize>>,
) -> Vec<EntropyMatch> {
    // Stable public signature: defaults `allow_canonical_lift = false` so the
    // non-ML / no-model behaviour (and every caller pinned to this 9-arg form)
    // is byte-identical. The production scanner uses the lift-aware entry point
    // below when the MoE is authoritative.
    find_entropy_secrets_with_canonical_lift(
        text,
        min_length,
        context_lines,
        entropy_threshold,
        keyword_free_threshold,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
        skip_lines,
        false,
    )
}

/// CredData recall lane (candidate GENERATION). Identical to
/// [`find_entropy_secrets_with_threshold`] but with an explicit
/// `allow_canonical_lift` switch: when `true`, a STRONG credential-anchored line
/// (`is_credential_context`) is allowed to GENERATE a candidate whose value is a
/// canonical hash/UUID/serial shape, so the downstream MoE can arbitrate it.
///
/// This closes the root candidate-generation gap for the CredData `UUID` and
/// `hex64` (AES-256 key) miss classes, where the value is dropped at the
/// generation source by [`is_canonical_non_secret_shape`] before any candidate
/// is produced — so no amount of downstream model authority can recover it.
///
/// `allow_canonical_lift` is wired from `ml_enabled && entropy_ml_authoritative`
/// at the call site (`engine::phase2_entropy`). With it `false` (the default,
/// the non-ML path, the high-precision preset) the behaviour is byte-identical
/// to the strict gate — the SecretBench-mirror precision is preserved because
/// the lift never engages without the model that earns it. The keyword-FREE
/// candidate path NEVER lifts: a value with no credential anchor has no positive
/// evidence, so canonical hash/UUID shapes stay suppressed at the source there.
#[allow(clippy::too_many_arguments)]
pub(crate) fn find_entropy_secrets_with_canonical_lift(
    text: &str,
    min_length: usize,
    context_lines: usize,
    entropy_threshold: f64,
    keyword_free_threshold: f64,
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
    skip_lines: Option<&std::collections::HashSet<usize>>,
    allow_canonical_lift: bool,
) -> Vec<EntropyMatch> {
    let lines: Vec<&str> = text.lines().collect();
    let line_offsets = crate::pipeline::compute_line_offsets(text);
    find_entropy_secrets_with_canonical_lift_and_lines(
        &lines,
        &line_offsets,
        min_length,
        context_lines,
        entropy_threshold,
        keyword_free_threshold,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
        skip_lines,
        allow_canonical_lift,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn find_entropy_secrets_with_canonical_lift_and_lines(
    lines: &[&str],
    line_offsets: &[usize],
    min_length: usize,
    context_lines: usize,
    entropy_threshold: f64,
    keyword_free_threshold: f64,
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
    skip_lines: Option<&std::collections::HashSet<usize>>,
    allow_canonical_lift: bool,
) -> Vec<EntropyMatch> {
    // The explicit `keyword_free_threshold` is authoritative here — do NOT
    // re-derive it from the generic-secret spec. The spec's `entropy_very_high`
    // is the single-owner DEFAULT and is read in ONE place, the no-threshold
    // convenience entry `find_entropy_secrets` (which passes it in as this
    // param). Callers that pass an ADJUSTED threshold rely on it: the production
    // `phase2_entropy` lowers it to `SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD`
    // on sensitive paths (a recall boost), and a Tier-A operator can RAISE it for
    // a stricter scan. A second spec read here silently clobbered both — a dead
    // knob (WIRING) and a lost sensitive-file recall boost.
    assert!(
        line_offsets.len() >= lines.len(),
        "entropy line offsets must cover every split line"
    );
    let keyword_lines = find_keyword_assignment_lines(lines, secret_keywords);
    find_entropy_secrets_with_precomputed_keywords(
        lines,
        line_offsets,
        &keyword_lines,
        min_length,
        context_lines,
        entropy_threshold,
        keyword_free_threshold,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
        skip_lines,
        allow_canonical_lift,
    )
}

/// Same as [`find_entropy_secrets_with_canonical_lift_and_lines`] but accepts
/// pre-computed keyword assignment lines, avoiding the O(lines × keywords)
/// `find_keyword_assignment_lines` scan when the caller already has the result.
/// This is the primary entry point for `scan_entropy_fallback`, which computes
/// keyword lines once and reuses them across the appropriateness gate, the
/// lower-dash app-password gate, and the full entropy scan.
#[allow(clippy::too_many_arguments)]
pub(crate) fn find_entropy_secrets_with_precomputed_keywords(
    lines: &[&str],
    line_offsets: &[usize],
    keyword_lines: &[(usize, &str)],
    min_length: usize,
    context_lines: usize,
    entropy_threshold: f64,
    keyword_free_threshold: f64,
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
    skip_lines: Option<&std::collections::HashSet<usize>>,
    allow_canonical_lift: bool,
) -> Vec<EntropyMatch> {
    find_entropy_secrets_with_precomputed_keywords_and_policy(
        lines,
        line_offsets,
        keyword_lines,
        min_length,
        context_lines,
        entropy_threshold,
        keyword_free_threshold,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
        skip_lines,
        allow_canonical_lift,
        None,
    )
}

/// Production sibling of [`find_entropy_secrets_with_precomputed_keywords`]
/// that resolves all detector-specific thresholds from the active compiled
/// corpus rather than the embedded defaults.
#[allow(clippy::too_many_arguments)]
pub(crate) fn find_entropy_secrets_with_precomputed_keywords_and_policy(
    lines: &[&str],
    line_offsets: &[usize],
    keyword_lines: &[(usize, &str)],
    min_length: usize,
    context_lines: usize,
    entropy_threshold: f64,
    keyword_free_threshold: f64,
    secret_keywords: &[String],
    test_keywords: &[String],
    placeholder_keywords: &[String],
    skip_lines: Option<&std::collections::HashSet<usize>>,
    allow_canonical_lift: bool,
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) -> Vec<EntropyMatch> {
    assert!(
        line_offsets.len() >= lines.len(),
        "entropy line offsets must cover every split line"
    );
    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();

    scan_keyword_contexts(
        lines,
        line_offsets,
        keyword_lines,
        min_length,
        context_lines,
        entropy_threshold,
        &mut seen,
        &mut matches,
        secret_keywords,
        test_keywords,
        placeholder_keywords,
        skip_lines,
        allow_canonical_lift,
        active_policy,
    );
    scan_keyword_free_candidates(
        lines,
        line_offsets,
        entropy_threshold,
        keyword_free_threshold,
        &mut seen,
        &mut matches,
        placeholder_keywords,
        skip_lines,
        active_policy,
    );
    matches
}

#[allow(clippy::too_many_arguments)]
fn scan_keyword_contexts(
    lines: &[&str],
    line_offsets: &[usize],
    keyword_lines: &[(usize, &str)],
    min_length: usize,
    context_lines: usize,
    entropy_threshold: f64,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
    secret_keywords: &[String],
    _test_keywords: &[String],
    placeholder_keywords: &[String],
    skip_lines: Option<&std::collections::HashSet<usize>>,
    allow_canonical_lift: bool,
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) {
    for (keyword_line_index, keyword_line) in keyword_lines {
        let context = keyword_context_with_policy(
            keyword_line,
            min_length,
            entropy_threshold,
            secret_keywords,
            allow_canonical_lift,
            active_policy,
        );
        let start = keyword_line_index.saturating_sub(context_lines);
        let end = (*keyword_line_index + context_lines + 1).min(lines.len());
        for line_idx in start..end {
            if let Some(skip) = skip_lines {
                if skip.contains(&line_idx) {
                    continue;
                }
            }
            collect_line_candidates(
                lines[line_idx],
                line_idx,
                line_offsets[line_idx],
                &context,
                seen,
                matches,
                placeholder_keywords,
                active_policy,
            );
        }
    }
}

/// 256-byte lookup table for fast byte classification in the entropy scan.
/// Each byte is classified with bit flags:
/// - bit 0 (1): ASCII whitespace (space, tab, newline, CR)
/// - bit 1 (2): entropy candidate byte (alphanumeric + -_+/=.:!@#$%^&*)
/// - bit 2 (4): trigger byte (=, :, ", ', <) — required by `extract_candidates`
///
/// Using a lookup table instead of `is_ascii_alphanumeric()` + `matches!()`
/// per byte cuts the per-line byte scan from ~3-5 comparisons/byte to a single
/// table lookup, saving ~15ms across 9 windows at 8 MiB.
pub(super) const BYTE_CLASS: [u8; 256] = {
    let mut t = [0u8; 256];
    // Whitespace
    t[b' ' as usize] |= 1;
    t[b'\t' as usize] |= 1;
    t[b'\n' as usize] |= 1;
    t[b'\r' as usize] |= 1;
    t[0x0b] |= 1; // vertical tab
    t[0x0c] |= 1; // form feed
                  // Trigger bytes: =, :, ", ', <
    t[b'=' as usize] |= 4;
    t[b':' as usize] |= 4;
    t[b'"' as usize] |= 4;
    t[b'\'' as usize] |= 4;
    t[b'<' as usize] |= 4;
    // Entropy candidate bytes: alphanumeric + -_+/=.:!@#$%^&*
    // Digits 0-9
    let mut i = b'0' as usize;
    while i <= b'9' as usize {
        t[i] |= 2;
        i += 1;
    }
    // Uppercase A-Z
    i = b'A' as usize;
    while i <= b'Z' as usize {
        t[i] |= 2;
        i += 1;
    }
    // Lowercase a-z
    i = b'a' as usize;
    while i <= b'z' as usize {
        t[i] |= 2;
        i += 1;
    }
    // Symbol set
    t[b'-' as usize] |= 2;
    t[b'_' as usize] |= 2;
    t[b'+' as usize] |= 2;
    t[b'/' as usize] |= 2;
    t[b'=' as usize] |= 2;
    t[b'.' as usize] |= 2;
    t[b':' as usize] |= 2;
    t[b'!' as usize] |= 2;
    t[b'@' as usize] |= 2;
    t[b'#' as usize] |= 2;
    t[b'$' as usize] |= 2;
    t[b'%' as usize] |= 2;
    t[b'^' as usize] |= 2;
    t[b'&' as usize] |= 2;
    t[b'*' as usize] |= 2;
    t
};

fn scan_keyword_free_candidates(
    lines: &[&str],
    line_offsets: &[usize],
    entropy_threshold: f64,
    keyword_free_threshold: f64,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
    placeholder_keywords: &[String],
    skip_lines: Option<&std::collections::HashSet<usize>>,
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) {
    let effective_keyword_free_threshold = keyword_free_threshold.max(entropy_threshold + 1.0);
    let spec = get_spec(active_policy, crate::detector_ids::GENERIC_SECRET);
    let keyword_free_min_len = spec
        .and_then(|s| s.keyword_free_min_len)
        .map_or(KEYWORD_FREE_MIN_LEN, |min_len| min_len);
    let generic_keyword_secret_min_len =
        get_spec(active_policy, crate::detector_ids::GENERIC_KEYWORD_SECRET)
            .and_then(|s| s.keyword_free_min_len)
            .map_or(KEYWORD_FREE_MIN_LEN, |min_len| min_len);
    let keyword_free_context = KeywordContext {
        keyword: KEYWORD_FREE_LABEL.to_string(),
        threshold: effective_keyword_free_threshold,
        min_len: keyword_free_min_len,
        is_credential_context: false,
        // Keyword-FREE: no credential anchor ⇒ no positive evidence ⇒ the
        // canonical hash/UUID-shape gate stays strict here unconditionally,
        // regardless of model authority. The lift is anchor-gated.
        allow_canonical_shapes: false,
    };
    let isolated_token_context =
        isolated_bare_keyword_context(entropy_threshold, generic_keyword_secret_min_len);
    let isolated_min_len = isolated_token_context.min_len;
    for (line_idx, line) in lines.iter().enumerate() {
        if let Some(skip) = skip_lines {
            if skip.contains(&line_idx) {
                continue;
            }
        }
        // Single innocuous check for both paths (was called twice, once per
        // collect function). This is the single biggest per-line CPU saving
        // in the keyword-free scan: `is_likely_innocuous_line` does trim +
        // URI checks + import-prefix scan + hash-label scan + 40-hex check.
        if is_likely_innocuous_line(line) {
            continue;
        }
        // Single-pass byte scan using a 256-entry lookup table for fast
        // classification. Tracks three necessary conditions simultaneously:
        // 1. has_trigger: line contains '=', ':', '"', '\'', or '<'
        // 2. max_entropy_run: longest run of consecutive entropy candidate bytes
        // 3. max_nonws_run: longest non-whitespace run
        let bytes = line.as_bytes();
        let mut has_trigger = false;
        let mut max_entropy_run = 0usize;
        let mut cur_entropy_run = 0usize;
        let mut max_nonws_run = 0usize;
        let mut cur_nonws_run = 0usize;
        for &b in bytes {
            let class = BYTE_CLASS[b as usize];
            if class & 1 != 0 {
                // whitespace
                if cur_entropy_run > max_entropy_run {
                    max_entropy_run = cur_entropy_run;
                }
                cur_entropy_run = 0;
                if cur_nonws_run > max_nonws_run {
                    max_nonws_run = cur_nonws_run;
                }
                cur_nonws_run = 0;
            } else {
                cur_nonws_run += 1;
                if class & 2 != 0 {
                    cur_entropy_run += 1;
                } else {
                    if cur_entropy_run > max_entropy_run {
                        max_entropy_run = cur_entropy_run;
                    }
                    cur_entropy_run = 0;
                }
                if !has_trigger && class & 4 != 0 {
                    has_trigger = true;
                }
            }
        }
        if cur_entropy_run > max_entropy_run {
            max_entropy_run = cur_entropy_run;
        }
        if cur_nonws_run > max_nonws_run {
            max_nonws_run = cur_nonws_run;
        }
        // Isolated-bare path: needs a non-whitespace run ≥ isolated_min_len.
        // Use max_nonws_run (not max_entropy_run) because isolated_bare_candidate
        // accepts tokens with non-entropy bytes like `()` — the byte set is
        // wider than is_entropy_candidate_byte. But also require
        // max_entropy_run ≥ isolated_min_len as a fast skip for lines where
        // even the longest entropy run is too short, since the isolated-bare
        // path's `isolated_bare_candidate` requires alpha+digit or symbolic
        // opacity, which implies entropy bytes.
        let special_shape_may_cross_minimum = isolated_min_len
            > super::isolated::ISOLATED_SPECIAL_SHAPE_MIN_LEN
            && max_nonws_run >= super::isolated::ISOLATED_SPECIAL_SHAPE_MIN_LEN;
        if max_nonws_run >= isolated_min_len || special_shape_may_cross_minimum {
            collect_isolated_bare_candidates_inner(
                line,
                line_idx,
                line_offsets[line_idx],
                &isolated_token_context,
                seen,
                matches,
                placeholder_keywords,
            );
        }
        // Keyword-free path: `extract_candidates` + `push_candidate` checks
        // `cleaned.len() < keyword_free_min_len`. A candidate of length ≥
        // keyword_free_min_len that is a plausible secret consists entirely of
        // entropy candidate bytes, so max_entropy_run ≥ keyword_free_min_len
        // is a necessary condition. Skip extraction for lines without it.
        //
        // DOGFOOD EXEMPTION: when dogfood telemetry is enabled, we must still
        // process triggered lines with short entropy runs because
        // `extract_candidates_internal` records line-level rejections (e.g.
        // `ConcatenationFragmentLine`) BEFORE the per-candidate length check.
        // Skipping such lines would lose suppression events that are visible
        // to the dogfood pipeline. The prefilter only applies in production
        // (dogfood disabled) where suppression events are not recorded.
        let keyword_free_admit = if crate::telemetry::is_dogfood_enabled() {
            has_trigger
        } else {
            has_trigger && max_entropy_run >= keyword_free_min_len
        };
        if keyword_free_admit {
            collect_line_candidates_inner(
                line,
                line_idx,
                line_offsets[line_idx],
                &keyword_free_context,
                seen,
                matches,
                placeholder_keywords,
                active_policy,
            );
        }
    }
}

#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
#[allow(dead_code)] // Retained as convenience wrapper; production uses _with_precomputed_keywords
pub(crate) fn has_lower_dash_app_password_candidate_with_lines(
    lines: &[&str],
    config: &crate::ScannerConfig,
) -> bool {
    let keyword_lines = find_keyword_assignment_lines(lines, &config.secret_keywords);
    has_lower_dash_app_password_candidate_with_precomputed_keywords(lines, &keyword_lines, config)
}

/// Same as [`has_lower_dash_app_password_candidate_with_lines`] but accepts
/// pre-computed keyword assignment lines, avoiding the redundant
/// `find_keyword_assignment_lines` scan when the caller already has the result.
#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) fn has_lower_dash_app_password_candidate_with_precomputed_keywords(
    _lines: &[&str],
    keyword_lines: &[(usize, &str)],
    config: &crate::ScannerConfig,
) -> bool {
    has_lower_dash_app_password_candidate_with_precomputed_keywords_and_policy(
        keyword_lines,
        config,
        None,
    )
}

/// Production sibling of
/// [`has_lower_dash_app_password_candidate_with_precomputed_keywords`] that
/// resolves the prefilter's detector thresholds from the active corpus. The
/// prefilter can decide whether phase 2 runs at all, so consulting embedded
/// defaults here would be a silent policy override rather than an optimization.
#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) fn has_lower_dash_app_password_candidate_with_precomputed_keywords_and_policy(
    keyword_lines: &[(usize, &str)],
    config: &crate::ScannerConfig,
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) -> bool {
    for (_, keyword_line) in keyword_lines {
        if is_likely_innocuous_line(keyword_line) {
            continue;
        }
        let context = keyword_context_with_policy(
            keyword_line,
            config.min_secret_len,
            config.entropy_threshold,
            &config.secret_keywords,
            false,
            active_policy,
        );
        let detector = get_spec(
            active_policy,
            classify_keyword_to_detector_id(&context.keyword),
        );
        for candidate in extract_candidates(
            keyword_line,
            context.min_len,
            &config.placeholder_keywords,
            context.is_credential_context,
            false,
            detector,
        ) {
            let entropy = shannon_entropy(candidate.as_bytes());
            if lower_dash_app_password_floor_met(&candidate, entropy)
                && candidate_is_plausible_with_policy(
                    &candidate,
                    entropy,
                    &context,
                    &config.placeholder_keywords,
                    active_policy,
                )
            {
                return true;
            }
        }
    }
    false
}

fn collect_line_candidates(
    line: &str,
    line_idx: usize,
    line_offset: usize,
    context: &KeywordContext,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
    placeholder_keywords: &[String],
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) {
    if is_likely_innocuous_line(line) {
        return;
    }
    collect_line_candidates_inner(
        line,
        line_idx,
        line_offset,
        context,
        seen,
        matches,
        placeholder_keywords,
        active_policy,
    );
}

/// Inner extraction logic without the `is_likely_innocuous_line` gate.
/// The caller MUST have already verified the line is not innocuous.
/// Used by `scan_keyword_free_candidates` which performs the innocuous check
/// once per line for both the isolated-bare and line-candidate paths.
fn collect_line_candidates_inner(
    line: &str,
    line_idx: usize,
    line_offset: usize,
    context: &KeywordContext,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
    placeholder_keywords: &[String],
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) {
    let detector = get_spec(
        active_policy,
        classify_keyword_to_detector_id(&context.keyword),
    );
    let candidates = if crate::telemetry::is_dogfood_enabled() {
        let extracted = extract_candidates_with_rejections(
            line,
            context.min_len,
            placeholder_keywords,
            context.is_credential_context,
            context.allow_canonical_shapes,
            detector,
        );
        for rejection in &extracted.rejections {
            let ctx = crate::adjudicate::MatchCtx::for_entropy_generation(
                crate::adjudicate::EntropyGenerationSignal::SuppressionStage(rejection.stage_id),
            );
            crate::adjudicate::record_suppression(None, &rejection.value, &ctx);
        }
        extracted.candidates
    } else {
        extract_candidates(
            line,
            context.min_len,
            placeholder_keywords,
            context.is_credential_context,
            context.allow_canonical_shapes,
            detector,
        )
    };

    for candidate in candidates {
        let entropy = shannon_entropy(candidate.as_bytes());
        if let Some(stage_id) = candidate_plausibility_rejection_stage_with_policy(
            &candidate,
            entropy,
            context,
            placeholder_keywords,
            active_policy,
        ) {
            if crate::telemetry::is_dogfood_enabled() {
                let ctx = crate::adjudicate::MatchCtx::for_entropy_generation(
                    crate::adjudicate::EntropyGenerationSignal::SuppressionStage(stage_id),
                );
                crate::adjudicate::record_suppression(None, &candidate, &ctx);
            }
            continue;
        }
        if seen.contains(candidate.as_str()) {
            continue;
        }
        seen.insert(candidate.clone());
        matches.push(EntropyMatch {
            value: candidate,
            entropy,
            keyword: context.keyword.clone(),
            line: line_idx + FIRST_SOURCE_LINE_NUMBER,
            offset: line_offset,
        });
    }
}

pub(crate) fn candidate_is_plausible(
    candidate: &str,
    entropy: f64,
    context: &KeywordContext,
    placeholder_keywords: &[String],
) -> bool {
    candidate_plausibility_rejection_stage(candidate, entropy, context, placeholder_keywords)
        .is_none()
}

fn candidate_is_plausible_with_policy(
    candidate: &str,
    entropy: f64,
    context: &KeywordContext,
    placeholder_keywords: &[String],
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) -> bool {
    candidate_plausibility_rejection_stage_with_policy(
        candidate,
        entropy,
        context,
        placeholder_keywords,
        active_policy,
    )
    .is_none()
}

pub(crate) fn candidate_plausibility_rejection_stage(
    candidate: &str,
    entropy: f64,
    context: &KeywordContext,
    placeholder_keywords: &[String],
) -> Option<StageId> {
    candidate_plausibility_rejection_stage_with_policy(
        candidate,
        entropy,
        context,
        placeholder_keywords,
        None,
    )
}

fn candidate_plausibility_rejection_stage_with_policy(
    candidate: &str,
    entropy: f64,
    context: &KeywordContext,
    placeholder_keywords: &[String],
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) -> Option<StageId> {
    let detector_id = classify_keyword_to_detector_id(&context.keyword);
    let spec = get_spec(active_policy, detector_id);
    let keyword_free_min_len = spec
        .and_then(|s| s.keyword_free_min_len)
        .map_or(KEYWORD_FREE_MIN_LEN, |min_len| min_len);
    let credential_context_min_len = spec
        .and_then(|s| s.min_len)
        .map_or(CREDENTIAL_CONTEXT_MIN_LEN, |min_len| min_len);

    if crate::suppression::shape::is_structured_dotted_token(candidate) {
        if candidate.len() < keyword_free_min_len.min(context.min_len) {
            return Some(StageId::EntropyValueShape(
                EntropyShapeStage::StructuredDottedTooShort,
            ));
        }
        // A JWT/Discord-shaped value gets the shape-specific length allowance,
        // not blanket admission. It must still clear the active entropy floor
        // and downstream plausibility gates; otherwise repeated-segment dotted
        // placeholders fail open as secrets.
    }
    if entropy < context.threshold {
        return Some(StageId::EntropyBelowFloor);
    }
    if context.is_credential_context {
        // A bare credential keyword (`api_key=`, `token:`, `secret=`) is a
        // weak anchor: the mirror wraps every digest / UUID / license-serial
        // negative inside an assignment, so credential context alone would
        // re-admit sha256/sha1/uuid/npm-integrity/license-key shapes as FPs.
        // (Commit 19c9d668 lifted the digest blacklist in credential context
        // for +60 TP, but its protection sits OUTSIDE the anchor and never
        // reaches the wrapped mirror negatives.) The keyword anchor here is
        // generic, never a service-specific regex match, so it is too weak to
        // override a perfect canonical shape. Drop the EXACT canonical shapes
        // even with the anchor; a real high-entropy key under a service anchor
        // is matched by its detector regex, not this generic entropy path.
        //
        // CredData recall lane: when `allow_canonical_shapes` is set — i.e. the
        // MoE is the runtime precision authority AND a strong credential keyword
        // anchors this line — GENERATE the canonical-shape candidate anyway so
        // the model can arbitrate it. The CredData `UUID` and `hex64` (AES-256
        // key) miss classes are dropped HERE at the generation source; with the
        // model in scope the strict drop trades real recall (the value never
        // reaches the scorer) for a precision the MoE already provides. With the
        // flag unset (non-ML path) this is the byte-identical strict gate, so
        // the SecretBench-mirror precision — where `TOKEN=<32-hex>` is BOTH a
        // positive and a sha256/git-sha/k8s-uid negative — is unchanged.
        let canonical_lift = context.allow_canonical_shapes
            && canonical_shape_lift_allowed(candidate, &context.keyword);
        if !canonical_lift && is_canonical_non_secret_shape(candidate) {
            return Some(StageId::EntropyValueShape(
                EntropyShapeStage::CanonicalNonSecretShape,
            ));
        }
        return (candidate.len() < credential_context_min_len).then_some(
            StageId::EntropyValueShape(EntropyShapeStage::CredentialContextTooShort),
        );
    }
    if candidate.len() < keyword_free_min_len.min(context.min_len) {
        return Some(StageId::EntropyValueShape(
            EntropyShapeStage::KeywordFreeTooShort,
        ));
    }
    let plausibility_context = PlausibilityContext::new(
        context.is_credential_context,
        context.allow_canonical_shapes,
    )
    .with_detector(spec);
    if !is_secret_plausible(candidate, placeholder_keywords, plausibility_context) {
        return Some(StageId::EntropyValueShape(
            EntropyShapeStage::SecretPlausibilityRejected,
        ));
    }
    None
}

/// True when `value` is EXACTLY a canonical non-secret shape: a hash digest,
/// UUID, npm integrity string, or license serial. These keep their shape
/// regardless of any surrounding credential keyword, so a generic entropy
/// anchor must not re-admit them. Service-specific detector regexes (not this
/// path) own the rare case where such a shape really is a credential.
pub(crate) fn is_canonical_non_secret_shape(value: &str) -> bool {
    crate::suppression::shape::looks_like_entropy_canonical_non_secret_shape(value)
}

/// True iff the model-authoritative canonical-shape lift may release this exact
/// value shape under this exact keyword. The lift is intentionally narrower than
/// "credential context": mirror negatives wrap sha1/git SHAs in `api_key=` and
/// `secret=`, so hex40 must never lift, and sha256-length hex64 only lifts under
/// explicit cryptographic-key anchors where an AES-256/key-material value is a
/// plausible credential.
pub(crate) fn canonical_shape_lift_allowed(value: &str, keyword: &str) -> bool {
    if crate::suppression::shape::looks_like_entropy_uuid_shape(value) {
        return true;
    }
    if !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    match value.len() {
        // 32-hex key material is a documented recall surface under explicit
        // key-material anchors (`api_key`, `access_key`, ...), but broad
        // `token=` remains too weak and stays suppressed.
        32 => keyword_is_key_material(keyword),
        // 64-hex is sha256-shaped unless the keyword explicitly names key
        // material. `secret=` / `api_key=` are too broad and stay suppressed.
        64 => keyword_is_crypto_key_material(keyword),
        // 40 is sha1/git-commit SHA. 128 is sha512. Both stay canonical
        // non-secret shapes even under the model-authoritative lift.
        _ => false,
    }
}

pub(crate) fn keyword_is_crypto_key_material(keyword: &str) -> bool {
    [
        "encryptionkey",
        "masterkey",
        "signingkey",
        "privatekey",
        "secretkey",
        "sessionkey",
        "hmacsecret",
        "hmacsalt",
        "hmacseed",
        "passwordsalt",
        "salt",
        "nonce",
        "seed",
    ]
    .iter()
    .any(|needle| compact_keyword_contains(keyword, needle.as_bytes()))
}

pub(crate) fn keyword_is_key_material(keyword: &str) -> bool {
    [
        "apikey",
        "accesskey",
        "authkey",
        "privatekey",
        "signingkey",
        "encryptionkey",
        "masterkey",
        "secretkey",
        "sessionkey",
        "hmacsalt",
        "hmacseed",
        "passwordsalt",
        "salt",
        "nonce",
        "seed",
    ]
    .iter()
    .any(|needle| compact_keyword_contains(keyword, needle.as_bytes()))
}

/// True iff `needle` (already separator-free and ASCII-lowercase, as every
/// key-material literal above is) appears as a contiguous substring of `keyword`
/// once `keyword` is compacted the same way the literals were authored: `_`/`-`/
/// `.` dropped and ASCII-lowercased. Byte-identical to the old
/// `compact_keyword(keyword).contains(needle)` but with NO per-call `String`
/// allocation (Law 7: this runs per canonical-lift candidate). Mirrors the
/// compact-keyword matcher family in `engine::phase2_generic::keywords`
/// (`compact_keyword_eq`/`_ends_with`); see the backlog DEDUP task to hoist that
/// family to a shared low layer — `entropy` must not import `engine`.
fn compact_keyword_contains(keyword: &str, needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let bytes = keyword.as_bytes();
    let len = bytes.len();
    let mut start = 0;
    while start < len {
        if matches!(bytes[start], b'_' | b'-' | b'.') {
            start += 1;
            continue;
        }
        // Attempt to match `needle` beginning at this compacted character,
        // skipping separators between matched bytes exactly as the compacted
        // string would have collapsed them.
        let mut ki = start;
        let mut ni = 0;
        while ni < needle.len() && ki < len {
            let byte = bytes[ki];
            if matches!(byte, b'_' | b'-' | b'.') {
                ki += 1;
                continue;
            }
            if byte.to_ascii_lowercase() != needle[ni] {
                break;
            }
            ki += 1;
            ni += 1;
        }
        if ni == needle.len() {
            return true;
        }
        start += 1;
    }
    false
}

pub(crate) fn keyword_context(
    keyword_line: &str,
    min_length: usize,
    entropy_threshold: f64,
    secret_keywords: &[String],
    allow_canonical_lift: bool,
) -> KeywordContext {
    keyword_context_with_policy(
        keyword_line,
        min_length,
        entropy_threshold,
        secret_keywords,
        allow_canonical_lift,
        None,
    )
}

fn keyword_context_with_policy(
    keyword_line: &str,
    min_length: usize,
    entropy_threshold: f64,
    secret_keywords: &[String],
    allow_canonical_lift: bool,
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) -> KeywordContext {
    let line_bytes = keyword_line.as_bytes();
    let exact_assignment_keyword =
        crate::entropy::keywords::assignment_keyword_for_line(keyword_line);
    let keyword = exact_assignment_keyword
        .as_deref()
        .or_else(|| {
            secret_keywords
                .iter()
                .find(|keyword| crate::ascii_ci::ci_find_nonempty(line_bytes, keyword.as_bytes()))
                .map(|keyword| keyword.as_str())
        })
        .unwrap_or("unknown"); // LAW10: absent path/field => display placeholder; reporting-only, recall-safe
    let is_exact_credential_context = exact_assignment_keyword
        .as_deref()
        .is_some_and(crate::entropy::keywords::normalized_assignment_keyword_is_credential);
    let is_credential_context = is_exact_credential_context
        || crate::credential_context_keywords::credential_context_keywords()
            .iter()
            .any(|credential_keyword| {
                crate::ascii_ci::ci_find_nonempty(line_bytes, credential_keyword.as_bytes())
            });

    let detector_id = classify_keyword_to_detector_id(keyword);
    let spec = get_spec(active_policy, detector_id);
    let entropy_low = spec
        .and_then(|s| s.entropy_low)
        .map_or(LOW_ENTROPY_THRESHOLD, |threshold| threshold);
    let min_len = spec
        .and_then(|s| s.min_len)
        .map_or(CREDENTIAL_CONTEXT_MIN_LEN, |min_len| min_len);
    let entropy_high = spec
        .and_then(|s| s.entropy_high)
        .map_or(HIGH_ENTROPY_THRESHOLD, |threshold| threshold);

    // Keyword-anchored floor policy — a NAMED, tested rule, not a silent clamp.
    // Inside a credential-keyword context the keyword IS the positive evidence,
    // so the entropy bar is the LOW floor. The operator's Tier-A threshold
    // engages only when it is stricter than the blanket HIGH floor — that shared
    // decision lives in one owner, `operator_entropy_override` (see its doc). It
    // is honored verbatim when it overrides; otherwise the keyword floor is
    // `min(threshold, LOW)` for a finite request (a below-LOW request may still
    // loosen the recall-oriented keyword path) and LOW for a non-finite one.
    let operator_override = (entropy_threshold.is_finite() && entropy_threshold > entropy_high)
        .then_some(entropy_threshold);
    let base_threshold = match operator_override {
        Some(threshold) => threshold,
        None if entropy_threshold.is_finite() => entropy_threshold.min(entropy_low),
        None => entropy_low,
    };

    KeywordContext {
        keyword: keyword.to_string(),
        threshold: base_threshold,
        min_len: if is_credential_context {
            min_len
        } else {
            min_length
        },
        is_credential_context,
        // The canonical-shape generation lift engages ONLY when the MoE is the
        // runtime precision authority AND a strong credential keyword anchors
        // the line — both must hold, so a non-credential line never lifts even
        // under the model.
        allow_canonical_shapes: allow_canonical_lift && is_credential_context,
    }
}
