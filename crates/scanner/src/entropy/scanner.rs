use super::isolated::{
    collect_isolated_bare_candidates_inner, isolated_bare_keyword_context_with_shape,
};
#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) use super::isolated::{
    colon_separated_opaque_candidate, lower_dash_app_password_floor_met_with_policy,
    mixed_contiguous_token_floor_met, mixed_separator_token_floor_met,
    symbolic_alpha_only_opaque_candidate, symbolic_isolated_bare_candidate,
};
#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) use super::isolated::{
    has_isolated_bare_secret_candidate_with_lines_and_policy,
    has_isolated_bare_secret_candidate_with_policy,
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
    index: &'a crate::generic_keyword_owner::GenericOwningDetectorIndex,
    compiled: &'a crate::entropy::policy::CompiledEntropyPolicies,
    key_material: &'a crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicies,
}

impl<'a> ActiveDetectorPolicy<'a> {
    pub(crate) fn new(
        index: &'a crate::generic_keyword_owner::GenericOwningDetectorIndex,
        compiled: &'a crate::entropy::policy::CompiledEntropyPolicies,
        key_material: &'a crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicies,
    ) -> Self {
        Self {
            index,
            compiled,
            key_material,
        }
    }

    fn compiled_for_keyword(
        self,
        keyword: &str,
    ) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
        active_policy_detector_index(self.index, keyword).and_then(|index| self.compiled.get(index))
    }

    fn compiled_for_role(
        self,
        role: keyhog_core::EntropyDetectionRole,
    ) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
        let index = match role {
            keyhog_core::EntropyDetectionRole::KeywordFree => self.index.keyword_free_owner_index(),
            keyhog_core::EntropyDetectionRole::IsolatedBare => {
                self.index.isolated_bare_owner_index()
            }
            keyhog_core::EntropyDetectionRole::UnclaimedKeyword => {
                self.index.unclaimed_keyword_owner_index()
            }
        }?;
        self.compiled.get(index)
    }

    fn key_material_for_keyword(
        self,
        keyword: &str,
    ) -> Option<&'a crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy> {
        let index = self
            .index
            .canonical_index(keyword)
            .or_else(|| active_policy_detector_index(self.index, keyword))?;
        Some(self.key_material.get(index))
    }

    fn claims_keyword(self, keyword: &str) -> bool {
        self.index.claimed_policy_index(keyword).is_some()
    }
}

/// Resolve entropy policy from the compiled corpus. Synthetic paths have exact
/// owners, detector-declared keyword claims come next, and an unclaimed Tier-A
/// keyword retains the API-key compatibility policy before the generic-secret
/// fallback. This is the single resolver shared by generation and emission.
pub(crate) fn active_policy_detector_index(
    index: &crate::generic_keyword_owner::GenericOwningDetectorIndex,
    keyword: &str,
) -> Option<usize> {
    if keyword == KEYWORD_FREE_LABEL {
        return index.keyword_free_owner_index();
    }
    if keyword == crate::entropy::ISOLATED_BARE_ENTROPY_LABEL {
        return index.isolated_bare_owner_index();
    }
    index
        .claimed_policy_index(keyword)
        .or_else(|| index.unclaimed_keyword_owner_index())
}

fn embedded_spec_for_role(
    role: keyhog_core::EntropyDetectionRole,
) -> Option<&'static DetectorSpec> {
    keyhog_core::embedded_detector_specs()
        .iter()
        .find(|detector| detector.entropy_roles.contains(&role))
}

fn embedded_spec_for_keyword(keyword: &str) -> Option<&'static DetectorSpec> {
    static INDEX: std::sync::LazyLock<crate::generic_keyword_owner::GenericOwningDetectorIndex> =
        std::sync::LazyLock::new(|| {
            crate::generic_keyword_owner::GenericOwningDetectorIndex::build(
                keyhog_core::embedded_detector_specs(),
            )
            .unwrap_or_else(|error| {
                panic!("embedded detector entropy ownership is invalid: {error}")
            })
        });
    active_policy_detector_index(&INDEX, keyword)
        .and_then(|index| keyhog_core::embedded_detector_specs().get(index))
}

fn get_spec_for_keyword<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    keyword: &str,
) -> Option<&'a DetectorSpec> {
    match active_policy {
        Some(_) => None,
        None => embedded_spec_for_keyword(keyword),
    }
}

fn get_compiled_policy_for_keyword<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    keyword: &str,
) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
    active_policy.and_then(|policy| policy.compiled_for_keyword(keyword))
}

fn get_spec_for_role<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    role: keyhog_core::EntropyDetectionRole,
) -> Option<&'a DetectorSpec> {
    match active_policy {
        Some(_) => None,
        None => embedded_spec_for_role(role),
    }
}

fn get_compiled_policy_for_role<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    role: keyhog_core::EntropyDetectionRole,
) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
    active_policy.and_then(|policy| policy.compiled_for_role(role))
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
/// production credential anchor. The historical `allow_canonical_lift` flag is
/// accepted for API compatibility but detector policy remains authoritative.
/// Exposed (doc-hidden, via `testing::entropy_scanner`)
/// so unit tests can drive `candidate_is_plausible` through both the strict gate
/// and the model-arbitrated key-material lift.
#[doc(hidden)]
pub(crate) fn credential_keyword_context_with_lift(
    keyword: &str,
    _allow_canonical_lift: bool,
) -> KeywordContext {
    let spec = get_spec_for_keyword(None, keyword);
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
        // This constructor is used only by the testing facade, where the
        // historical lift switch remains useful for unit-gate coverage. The
        // production policy-aware context below always sets this false.
        allow_canonical_shapes: _allow_canonical_lift,
        entropy_shape: spec.and_then(keyhog_core::DetectorSpec::lower_dash_entropy_shape),
        plausibility_policy: None,
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
    let spec = get_spec_for_role(None, keyhog_core::EntropyDetectionRole::KeywordFree);
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
    // Stable public signature retained for callers that pass the historical
    // model-authority switch. Detector TOML remains authoritative in every
    // mode, so this compatibility entry point uses the same policy path.
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

/// Policy-aware entropy generation. The historical `allow_canonical_lift`
/// switch remains in the signature for compatibility, but cannot create or
/// widen canonical hex admission. Only the active detector's
/// `canonical_hex_key_material` declaration can release digest-shaped values;
/// UUIDs and serials remain suppressed in this generic path. The keyword-free
/// candidate path never has detector-owned key evidence and therefore never
/// lifts canonical shapes.
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
    // The explicit `keyword_free_threshold` is authoritative here, do NOT
    // re-derive it from the generic-secret spec. Callers resolve the relevant
    // corpus first: the convenience entry reads the embedded detector, while
    // production reads the compiled detector and applies its detector-relative
    // sensitive-path discount. Re-reading policy here would silently clobber
    // both custom corpora and the recall adjustment.
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
        Some(keyword_free_threshold),
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
    keyword_free_threshold: Option<f64>,
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
        let Some(context) = keyword_context_with_policy(
            keyword_line,
            min_length,
            entropy_threshold,
            secret_keywords,
            allow_canonical_lift,
            active_policy,
        ) else {
            continue;
        };
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
/// - bit 2 (4): trigger byte (=, :, ", ', <), required by `extract_candidates`
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
    keyword_free_threshold: Option<f64>,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
    placeholder_keywords: &[String],
    skip_lines: Option<&std::collections::HashSet<usize>>,
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) {
    let spec = get_spec_for_role(
        active_policy,
        keyhog_core::EntropyDetectionRole::KeywordFree,
    );
    let compiled_secret = get_compiled_policy_for_role(
        active_policy,
        keyhog_core::EntropyDetectionRole::KeywordFree,
    );
    let keyword_free_min_len = compiled_secret
        .map(|policy| policy.keyword_free_min_len)
        .or_else(|| {
            active_policy.is_none().then(|| {
                spec.and_then(|s| s.keyword_free_min_len)
                    .unwrap_or(KEYWORD_FREE_MIN_LEN)
            })
        });
    let generic_keyword_secret_spec = get_spec_for_role(
        active_policy,
        keyhog_core::EntropyDetectionRole::IsolatedBare,
    );
    let compiled_keyword_secret = get_compiled_policy_for_role(
        active_policy,
        keyhog_core::EntropyDetectionRole::IsolatedBare,
    );
    let keyword_free_enabled = keyword_free_threshold.is_some() && keyword_free_min_len.is_some();
    let generic_keyword_secret_min_len = compiled_keyword_secret
        .map(|policy| policy.keyword_free_min_len)
        .or_else(|| {
            active_policy.is_none().then(|| {
                generic_keyword_secret_spec
                    .and_then(|s| s.keyword_free_min_len)
                    .unwrap_or(KEYWORD_FREE_MIN_LEN)
            })
        });
    let isolated_bare_enabled = generic_keyword_secret_min_len.is_some();
    if !keyword_free_enabled && !isolated_bare_enabled {
        return;
    }
    let isolated_shape = compiled_keyword_secret
        .and_then(|policy| policy.entropy_shape)
        .or_else(|| {
            generic_keyword_secret_spec
                .and_then(keyhog_core::DetectorSpec::lower_dash_entropy_shape)
        });
    let keyword_free_context = keyword_free_threshold
        .filter(|_| keyword_free_enabled)
        .zip(keyword_free_min_len)
        .map(|(threshold, min_len)| KeywordContext {
            keyword: KEYWORD_FREE_LABEL.to_string(),
            threshold: threshold.max(entropy_threshold + 1.0),
            min_len,
            is_credential_context: false,
            // Keyword-free candidates have no anchor, so canonical shapes stay strict.
            allow_canonical_shapes: false,
            entropy_shape: compiled_secret
                .and_then(|policy| policy.entropy_shape)
                .or_else(|| spec.and_then(keyhog_core::DetectorSpec::lower_dash_entropy_shape)),
            plausibility_policy: compiled_secret.copied(),
        });
    let isolated_token_context = generic_keyword_secret_min_len.map(|min_len| {
        isolated_bare_keyword_context_with_shape(
            entropy_threshold,
            min_len,
            isolated_shape,
            compiled_keyword_secret.copied(),
        )
    });
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
        // accepts tokens with non-entropy bytes like `()`: the byte set is
        // wider than is_entropy_candidate_byte. But also require
        // max_entropy_run ≥ isolated_min_len as a fast skip for lines where
        // even the longest entropy run is too short, since the isolated-bare
        // path's `isolated_bare_candidate` requires alpha+digit or symbolic
        // opacity, which implies entropy bytes.
        if let Some(isolated_token_context) = isolated_token_context.as_ref() {
            let isolated_min_len = isolated_token_context.min_len;
            let special_shape_min_len = super::isolated::isolated_special_shape_min_len(
                isolated_token_context.entropy_shape.as_ref(),
                isolated_token_context.plausibility_policy.as_ref(),
            );
            let special_shape_may_cross_minimum =
                isolated_min_len > special_shape_min_len && max_nonws_run >= special_shape_min_len;
            if isolated_bare_enabled
                && (max_nonws_run >= isolated_min_len || special_shape_may_cross_minimum)
            {
                collect_isolated_bare_candidates_inner(
                    line,
                    line_idx,
                    line_offsets[line_idx],
                    isolated_token_context,
                    seen,
                    matches,
                    placeholder_keywords,
                );
            }
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
        let keyword_free_admit = if keyword_free_context.is_none() {
            false
        } else if crate::telemetry::is_dogfood_enabled() {
            has_trigger
        } else {
            has_trigger && keyword_free_min_len.is_some_and(|minimum| max_entropy_run >= minimum)
        };
        if let Some(keyword_free_context) =
            keyword_free_context.as_ref().filter(|_| keyword_free_admit)
        {
            collect_line_candidates_inner(
                line,
                line_idx,
                line_offsets[line_idx],
                keyword_free_context,
                seen,
                matches,
                placeholder_keywords,
                active_policy,
            );
        }
    }
}

/// Resolves the prefilter's detector thresholds from the active corpus using
/// precomputed keyword assignment lines. The
/// prefilter can decide whether phase 2 runs at all, so consulting embedded
/// defaults here would be a silent policy override rather than an optimization.
#[cfg(feature = "simd")]
pub(crate) fn has_lower_dash_app_password_candidate_with_precomputed_keywords_and_policy(
    keyword_lines: &[(usize, &str)],
    config: &crate::ScannerConfig,
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) -> bool {
    for (_, keyword_line) in keyword_lines {
        if is_likely_innocuous_line(keyword_line) {
            continue;
        }
        let Some(context) = keyword_context_with_policy(
            keyword_line,
            config.min_secret_len,
            config.entropy_threshold,
            &config.secret_keywords,
            false,
            active_policy,
        ) else {
            continue;
        };
        let detector = get_spec_for_keyword(active_policy, &context.keyword);
        let key_material_policy =
            active_policy.and_then(|policy| policy.key_material_for_keyword(&context.keyword));
        for candidate in extract_candidates(
            keyword_line,
            &context.keyword,
            context.min_len,
            &config.placeholder_keywords,
            context.is_credential_context,
            false,
            detector,
            get_compiled_policy_for_keyword(active_policy, &context.keyword),
            key_material_policy,
        ) {
            let entropy = shannon_entropy(candidate.as_bytes());
            if lower_dash_app_password_floor_met_with_policy(
                &candidate,
                entropy,
                context.entropy_shape.as_ref(),
            ) && candidate_is_plausible_with_policy(
                &candidate,
                entropy,
                &context,
                &config.placeholder_keywords,
                active_policy,
            ) {
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
    let detector = get_spec_for_keyword(active_policy, &context.keyword);
    let key_material_policy =
        active_policy.and_then(|policy| policy.key_material_for_keyword(&context.keyword));
    let candidates = if crate::telemetry::is_dogfood_enabled() {
        let extracted = extract_candidates_with_rejections(
            line,
            &context.keyword,
            context.min_len,
            placeholder_keywords,
            context.is_credential_context,
            context.allow_canonical_shapes,
            detector,
            get_compiled_policy_for_keyword(active_policy, &context.keyword),
            key_material_policy,
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
            &context.keyword,
            context.min_len,
            placeholder_keywords,
            context.is_credential_context,
            context.allow_canonical_shapes,
            detector,
            get_compiled_policy_for_keyword(active_policy, &context.keyword),
            key_material_policy,
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

#[cfg(feature = "simd")]
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
    let spec = get_spec_for_keyword(active_policy, &context.keyword);
    let key_material_policy =
        active_policy.and_then(|policy| policy.key_material_for_keyword(&context.keyword));
    let compiled = get_compiled_policy_for_keyword(active_policy, &context.keyword);
    if active_policy.is_some() && compiled.is_none() {
        return Some(StageId::EntropyPolicyUnavailable);
    }
    let keyword_free_min_len = compiled.map_or_else(
        || {
            spec.and_then(|s| s.keyword_free_min_len)
                .unwrap_or(KEYWORD_FREE_MIN_LEN)
        },
        |policy| policy.keyword_free_min_len,
    );
    let credential_context_min_len = compiled.map_or_else(
        || {
            spec.and_then(|s| s.min_len)
                .unwrap_or(CREDENTIAL_CONTEXT_MIN_LEN)
        },
        |policy| policy.min_len,
    );

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
        // Canonical pure-hex admission is detector-owned. Model authority may
        // arbitrate an admitted candidate, but cannot manufacture a missing
        // detector policy or widen its declared lengths/keywords.
        let detector_owned_lift = key_material_policy.map_or_else(
            || {
                spec.is_some_and(|detector| {
                    detector.allows_canonical_hex_key_material(&context.keyword, candidate)
                })
            },
            |policy| policy.allows_canonical_hex(&context.keyword, candidate),
        );
        let compatibility_lift = active_policy.is_none()
            && context.allow_canonical_shapes
            && canonical_shape_lift_allowed(candidate, &context.keyword);
        let canonical_lift = detector_owned_lift || compatibility_lift;
        if !canonical_lift && is_canonical_non_secret_shape(candidate) {
            return Some(StageId::EntropyValueShape(
                EntropyShapeStage::CanonicalNonSecretShape,
            ));
        }
        if candidate.len() < credential_context_min_len {
            return Some(StageId::EntropyValueShape(
                EntropyShapeStage::CredentialContextTooShort,
            ));
        }
        let plausibility_context =
            PlausibilityContext::new(true, canonical_lift).with_detector_policy(spec, compiled);
        return (!is_secret_plausible(candidate, placeholder_keywords, plausibility_context))
            .then_some(StageId::EntropyValueShape(
                EntropyShapeStage::SecretPlausibilityRejected,
            ));
    }
    if candidate.len() < keyword_free_min_len.min(context.min_len) {
        return Some(StageId::EntropyValueShape(
            EntropyShapeStage::KeywordFreeTooShort,
        ));
    }
    let plausibility_context = PlausibilityContext::new(context.is_credential_context, false)
        .with_detector_policy(spec, compiled);
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

/// Historical compatibility predicate used only by migration tests. Runtime
/// admission never calls this global keyword classifier; it uses the active
/// detector's `canonical_hex_key_material` policy instead.
pub(crate) fn canonical_shape_lift_allowed(value: &str, keyword: &str) -> bool {
    if crate::suppression::shape::looks_like_entropy_uuid_shape(value) {
        // A UUID remains an identifier even beside a generic credential word.
        // Providers that issue UUID-bodied credentials must declare that exact
        // syntax in their detector TOML; the generic entropy bridge cannot
        // distinguish those credentials from resource IDs, Kubernetes UIDs,
        // and ordinary application identifiers.
        return false;
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
/// family to a shared low layer: `entropy` must not import `engine`.
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
    .unwrap_or_else(|| KeywordContext {
        keyword: "unknown".to_string(),
        threshold: LOW_ENTROPY_THRESHOLD,
        min_len: min_length.max(CREDENTIAL_CONTEXT_MIN_LEN),
        is_credential_context: false,
        allow_canonical_shapes: allow_canonical_lift,
        entropy_shape: None,
        plausibility_policy: None,
    })
}

fn keyword_context_with_policy(
    keyword_line: &str,
    min_length: usize,
    entropy_threshold: f64,
    secret_keywords: &[String],
    _allow_canonical_lift: bool,
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) -> Option<KeywordContext> {
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
    let is_active_detector_context = exact_assignment_keyword
        .as_deref()
        .is_some_and(|keyword| active_policy.is_some_and(|policy| policy.claims_keyword(keyword)));
    let is_credential_context = is_exact_credential_context
        || is_active_detector_context
        || crate::credential_context_keywords::credential_context_keywords()
            .iter()
            .any(|credential_keyword| {
                crate::ascii_ci::ci_find_nonempty(line_bytes, credential_keyword.as_bytes())
            });

    let spec = get_spec_for_keyword(active_policy, keyword);
    let compiled = get_compiled_policy_for_keyword(active_policy, keyword);
    if active_policy.is_some() && compiled.is_none() {
        return None;
    }
    let entropy_low = compiled.map_or_else(
        || {
            spec.and_then(|s| s.entropy_low)
                .unwrap_or(LOW_ENTROPY_THRESHOLD)
        },
        |policy| policy.entropy_low,
    );
    let min_len = compiled.map_or_else(
        || {
            spec.and_then(|s| s.min_len)
                .unwrap_or(CREDENTIAL_CONTEXT_MIN_LEN)
        },
        |policy| policy.min_len,
    );
    let entropy_high = compiled.map_or_else(
        || {
            spec.and_then(|s| s.entropy_high)
                .unwrap_or(HIGH_ENTROPY_THRESHOLD)
        },
        |policy| policy.entropy_high,
    );

    // Keyword-anchored floor policy (a NAMED, tested rule, not a silent clamp).
    // Inside a credential-keyword context the keyword IS the positive evidence,
    // so the entropy bar is the LOW floor. The operator's Tier-A threshold
    // engages only when it is stricter than the blanket HIGH floor, that shared
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

    Some(KeywordContext {
        keyword: keyword.to_string(),
        threshold: base_threshold,
        min_len: if is_credential_context {
            min_len
        } else {
            min_length
        },
        is_credential_context,
        // Canonical pure-hex admission is detector-owned. The legacy model
        // authority flag cannot widen a missing or narrower TOML policy.
        allow_canonical_shapes: false,
        entropy_shape: compiled
            .and_then(|policy| policy.entropy_shape)
            .or_else(|| spec.and_then(keyhog_core::DetectorSpec::lower_dash_entropy_shape)),
        plausibility_policy: compiled.copied(),
    })
}
