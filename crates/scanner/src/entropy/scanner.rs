use super::isolated::{collect_isolated_bare_candidates_inner, isolated_bare_keyword_context};
#[cfg(feature = "entropy")]
pub(crate) use super::isolated::{
    colon_separated_opaque_candidate, lower_dash_app_password_floor_met_with_policy,
    mixed_contiguous_token_floor_met, mixed_separator_token_floor_met,
    symbolic_alpha_only_opaque_candidate_with_policy, symbolic_isolated_bare_candidate_with_policy,
};
#[cfg(feature = "entropy")]
pub(crate) use super::isolated::{
    has_isolated_bare_secret_candidate_with_lines_and_policy,
    has_isolated_bare_secret_candidate_with_policy,
};
use super::{keywords::*, shannon_entropy, EntropyMatch, FIRST_SOURCE_LINE_NUMBER};

/// Borrowed view of the detector corpus that actually compiled for this scan.
/// Production phase-2 paths pass this view so custom detector directories and
/// operator-composed specs remain authoritative. Stable public convenience
/// APIs pass `None` and retain the embedded-corpus defaults they historically
/// exposed.
#[derive(Clone, Copy)]
pub(crate) struct ActiveDetectorPolicy<'a> {
    index: &'a crate::generic_keyword_owner::GenericOwningDetectorIndex,
    detector_plans: &'a crate::detector_plan::CompiledDetectorPlans,
}

impl<'a> ActiveDetectorPolicy<'a> {
    pub(crate) fn new(
        index: &'a crate::generic_keyword_owner::GenericOwningDetectorIndex,
        detector_plans: &'a crate::detector_plan::CompiledDetectorPlans,
    ) -> Self {
        Self {
            index,
            detector_plans,
        }
    }

    fn compiled_for_keyword(
        self,
        keyword: &str,
    ) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
        active_policy_detector_index(self.index, keyword)
            .and_then(|index| self.detector_plans.get(index).entropy.as_ref())
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
        self.detector_plans.get(index).entropy.as_ref()
    }

    fn key_material_for_keyword(
        self,
        keyword: &str,
    ) -> Option<&'a crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy> {
        let index = self
            .index
            .canonical_index(keyword)
            .or_else(|| active_policy_detector_index(self.index, keyword))?;
        Some(&self.detector_plans.get(index).key_material)
    }

    fn claims_keyword(self, keyword: &str) -> bool {
        self.index.claimed_policy_index(keyword).is_some()
    }
}

/// Resolve entropy policy from the compiled corpus. Synthetic paths have exact
/// owners, detector-declared keyword claims come next, and an unclaimed Tier-A
/// keyword resolves to the detector that explicitly owns the unclaimed-keyword
/// role. This is the single resolver shared by generation and emission.
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

struct EmbeddedEntropyPolicies {
    index: crate::generic_keyword_owner::GenericOwningDetectorIndex,
    entropy: Box<[Option<crate::entropy::policy::CompiledEntropyPolicy>]>,
    key_material: Box<[crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy]>,
}

fn embedded_entropy_policies() -> &'static EmbeddedEntropyPolicies {
    static POLICIES: std::sync::LazyLock<EmbeddedEntropyPolicies> = std::sync::LazyLock::new(
        || {
            let detectors = keyhog_core::embedded_detector_specs();
            let index =
                match crate::generic_keyword_owner::GenericOwningDetectorIndex::build(detectors) {
                    Ok(index) => index,
                    Err(error) => {
                        panic!("embedded detector entropy ownership is invalid: {error}")
                    }
                };
            let entropy = detectors
                .iter()
                .map(
                    |detector| match crate::entropy::policy::compile_entropy_policy(detector) {
                        Ok(policy) => policy,
                        Err(error) => {
                            panic!("embedded detector entropy policy is invalid: {error}")
                        }
                    },
                )
                .collect();
            let key_material = detectors
                .iter()
                .map(|detector| {
                    match crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy::compile(
                        detector,
                    ) {
                        Ok(policy) => policy,
                        Err(error) => {
                            panic!("embedded detector key-material policy is invalid: {error}")
                        }
                    }
                })
                .collect();
            EmbeddedEntropyPolicies {
                index,
                entropy,
                key_material,
            }
        },
    );
    &POLICIES
}

fn get_compiled_policy_for_keyword<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    keyword: &str,
) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
    match active_policy {
        Some(policy) => policy.compiled_for_keyword(keyword),
        None => {
            let policies = embedded_entropy_policies();
            active_policy_detector_index(&policies.index, keyword)
                .and_then(|index| policies.entropy.get(index)?.as_ref())
        }
    }
}

fn get_compiled_policy_for_role<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    role: keyhog_core::EntropyDetectionRole,
) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
    match active_policy {
        Some(policy) => policy.compiled_for_role(role),
        None => {
            let policies = embedded_entropy_policies();
            let index = match role {
                keyhog_core::EntropyDetectionRole::KeywordFree => {
                    policies.index.keyword_free_owner_index()
                }
                keyhog_core::EntropyDetectionRole::IsolatedBare => {
                    policies.index.isolated_bare_owner_index()
                }
                keyhog_core::EntropyDetectionRole::UnclaimedKeyword => {
                    policies.index.unclaimed_keyword_owner_index()
                }
            }?;
            policies.entropy.get(index)?.as_ref()
        }
    }
}

fn get_key_material_policy_for_keyword<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    keyword: &str,
) -> Option<&'a crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy> {
    match active_policy {
        Some(policy) => policy.key_material_for_keyword(keyword),
        None => {
            let policies = embedded_entropy_policies();
            let index = policies
                .index
                .canonical_index(keyword)
                .or_else(|| active_policy_detector_index(&policies.index, keyword))?;
            policies.key_material.get(index)
        }
    }
}

use crate::adjudicate::{EntropyShapeStage, StageId};
use crate::entropy::plausibility::{is_secret_plausible, PlausibilityContext};

pub(crate) const KEYWORD_FREE_LABEL: &str = "none (high-entropy)";

#[derive(Clone, Copy)]
pub(crate) enum KeywordFreeLineScope {
    All,
    KeywordAssignments,
}

/// Build the same detector-owned credential context used by production.
#[doc(hidden)]
pub(crate) fn credential_keyword_context(keyword: &str) -> KeywordContext {
    let policy = match get_compiled_policy_for_keyword(None, keyword) {
        Some(policy) => policy,
        None => panic!(
            "embedded detector entropy policy is unavailable for keyword {keyword:?}; fix the owning detector TOML"
        ),
    };
    KeywordContext {
        keyword: keyword.to_string(),
        threshold: policy.entropy_low,
        min_len: policy.min_len,
        is_credential_context: true,
        plausibility_policy: *policy,
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
    let entropy_very_high =
        match get_compiled_policy_for_role(None, keyhog_core::EntropyDetectionRole::KeywordFree) {
            Some(policy) => policy.entropy_very_high,
            None => panic!(
                "embedded keyword-free entropy policy is unavailable; fix the owning detector TOML"
            ),
        };
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

/// Find entropy-based matches with an explicit detector floor for keyword-free
/// admission. The embedded role owner's compiled policy still composes that
/// floor with `entropy_threshold` and its detector-owned operator margin.
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
    let lines: Vec<&str> = text.lines().collect();
    let line_offsets = crate::pipeline::compute_line_offsets(text);
    find_entropy_secrets_with_lines(
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
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn find_entropy_secrets_with_lines(
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
) -> Vec<EntropyMatch> {
    // The explicit `keyword_free_threshold` is the authoritative detector-floor
    // component; do not re-derive it here. The compiled role owner still applies
    // its TOML-owned operator margin when building the keyword-free context.
    // Callers resolve the relevant corpus first: the convenience entry reads
    // the embedded detector, while production reads the compiled detector and
    // applies its detector-relative sensitive-path discount.
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
    )
}

/// Same as [`find_entropy_secrets_with_lines`] but accepts
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
        None,
        KeywordFreeLineScope::All,
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
    active_policy: Option<ActiveDetectorPolicy<'_>>,
    keyword_free_line_scope: KeywordFreeLineScope,
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
        active_policy,
    );
    scan_keyword_free_candidates(
        lines,
        line_offsets,
        keyword_lines,
        entropy_threshold,
        keyword_free_threshold,
        &mut seen,
        &mut matches,
        placeholder_keywords,
        skip_lines,
        active_policy,
        keyword_free_line_scope,
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
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) {
    for (keyword_line_index, keyword_line) in keyword_lines {
        let Some(context) = keyword_context_with_policy(
            keyword_line,
            min_length,
            entropy_threshold,
            secret_keywords,
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
/// Using a lookup table replaces several classifications per byte with one
/// table lookup on the entropy hot path.
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
    keyword_lines: &[(usize, &str)],
    entropy_threshold: f64,
    keyword_free_threshold: Option<f64>,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
    placeholder_keywords: &[String],
    skip_lines: Option<&std::collections::HashSet<usize>>,
    active_policy: Option<ActiveDetectorPolicy<'_>>,
    keyword_free_line_scope: KeywordFreeLineScope,
) {
    let compiled_secret = get_compiled_policy_for_role(
        active_policy,
        keyhog_core::EntropyDetectionRole::KeywordFree,
    );
    let keyword_free_min_len = compiled_secret.map(|policy| policy.keyword_free_min_len);
    let keyword_free_operator_margin =
        compiled_secret.and_then(|policy| policy.keyword_free_operator_margin);
    let compiled_keyword_secret = get_compiled_policy_for_role(
        active_policy,
        keyhog_core::EntropyDetectionRole::IsolatedBare,
    );
    let keyword_free_enabled = keyword_free_threshold.is_some()
        && keyword_free_min_len.is_some()
        && keyword_free_operator_margin.is_some();
    let isolated_bare_enabled = compiled_keyword_secret.is_some();
    if !keyword_free_enabled && !isolated_bare_enabled {
        return;
    }
    let keyword_free_context = keyword_free_threshold
        .filter(|_| keyword_free_enabled)
        .zip(keyword_free_min_len)
        .and_then(|(threshold, min_len)| {
            let compiled = compiled_secret?;
            Some(KeywordContext {
                keyword: KEYWORD_FREE_LABEL.to_string(),
                threshold: compiled.keyword_free_effective_floor(threshold, entropy_threshold)?,
                min_len,
                is_credential_context: false,
                plausibility_policy: *compiled,
            })
        });
    let isolated_token_context = compiled_keyword_secret.map(|compiled| {
        isolated_bare_keyword_context(entropy_threshold, compiled.keyword_free_min_len, *compiled)
    });
    let isolated_admission_lengths = isolated_token_context.as_ref().map(|context| {
        (
            context.min_len,
            super::isolated::isolated_special_shape_min_len(
                context.plausibility_policy.entropy_shape.as_ref(),
                &context.plausibility_policy,
            ),
        )
    });
    let dogfood_enabled = crate::telemetry::is_dogfood_enabled();
    let mut keyword_line_cursor = 0usize;
    for (line_idx, line) in lines.iter().enumerate() {
        if matches!(
            keyword_free_line_scope,
            KeywordFreeLineScope::KeywordAssignments
        ) {
            while keyword_line_cursor < keyword_lines.len()
                && keyword_lines[keyword_line_cursor].0 < line_idx
            {
                keyword_line_cursor += 1;
            }
            if keyword_line_cursor == keyword_lines.len()
                || keyword_lines[keyword_line_cursor].0 != line_idx
            {
                continue;
            }
        }
        if let Some(skip) = skip_lines {
            if skip.contains(&line_idx) {
                continue;
            }
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
        // wider than is_entropy_candidate_byte. The below-normal-minimum
        // exception is narrower: every detector-owned lower-dash or symbolic
        // special-shape byte belongs to BYTE_CLASS, so its full minimum must be
        // one contiguous entropy run before the candidate visitor can matter.
        let isolated_admit =
            isolated_admission_lengths.is_some_and(|(isolated_min_len, special_shape_min_len)| {
                let special_shape_may_cross_minimum = isolated_min_len > special_shape_min_len
                    && max_entropy_run >= special_shape_min_len;
                isolated_bare_enabled
                    && (max_nonws_run >= isolated_min_len || special_shape_may_cross_minimum)
            });
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
        } else if dogfood_enabled {
            has_trigger
        } else {
            has_trigger && keyword_free_min_len.is_some_and(|minimum| max_entropy_run >= minimum)
        };
        if !isolated_admit && !keyword_free_admit {
            continue;
        }
        // Innocuous classification is more expensive than the byte admission
        // proof above. Run it only for a line that can reach either emitter.
        if is_likely_innocuous_line(line) {
            continue;
        }
        if isolated_admit {
            if let Some(isolated_token_context) = isolated_token_context.as_ref() {
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
#[cfg(feature = "entropy")]
pub(crate) fn has_lower_dash_app_password_candidate_with_precomputed_keywords_and_policy(
    keyword_lines: &[(usize, &str)],
    config: &crate::ScannerConfig,
    active_policy: Option<ActiveDetectorPolicy<'_>>,
    excluded_lines: &std::collections::HashSet<usize>,
) -> bool {
    for (line_index, keyword_line) in keyword_lines {
        if excluded_lines.contains(line_index) {
            continue;
        }
        if is_likely_innocuous_line(keyword_line) {
            continue;
        }
        let Some(context) = keyword_context_with_policy(
            keyword_line,
            config.min_secret_len,
            config.entropy_threshold,
            &config.secret_keywords,
            active_policy,
        ) else {
            continue;
        };
        let key_material_policy =
            get_key_material_policy_for_keyword(active_policy, &context.keyword);
        for candidate in extract_candidates(
            keyword_line,
            &context.keyword,
            context.min_len,
            &config.placeholder_keywords,
            context.is_credential_context,
            &context.plausibility_policy,
            key_material_policy,
        ) {
            let entropy = shannon_entropy(candidate.as_bytes());
            if lower_dash_app_password_floor_met_with_policy(
                &candidate,
                entropy,
                context.plausibility_policy.entropy_shape.as_ref(),
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
    let key_material_policy = get_key_material_policy_for_keyword(active_policy, &context.keyword);
    let candidates = if crate::telemetry::is_dogfood_enabled() {
        let extracted = extract_candidates_with_rejections(
            line,
            &context.keyword,
            context.min_len,
            placeholder_keywords,
            context.is_credential_context,
            &context.plausibility_policy,
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
            &context.plausibility_policy,
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
#[cfg(feature = "entropy")]
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
    let key_material_policy = get_key_material_policy_for_keyword(active_policy, &context.keyword);
    let Some(compiled) = get_compiled_policy_for_keyword(active_policy, &context.keyword) else {
        return Some(StageId::EntropyPolicyUnavailable);
    };
    let keyword_free_min_len = compiled.keyword_free_min_len;
    let credential_context_min_len = compiled.min_len;

    let structured_dotted = crate::suppression::shape::is_structured_dotted_token(candidate);
    if structured_dotted {
        if candidate.len() < compiled.structured_dotted_min_len {
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
        let detector_owned_admission = key_material_policy
            .is_some_and(|policy| policy.allows_canonical_hex(&context.keyword, candidate));
        let canonical_policy_admission = detector_owned_admission;
        if !canonical_policy_admission && is_canonical_non_secret_shape(candidate) {
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
            PlausibilityContext::from_compiled(true, canonical_policy_admission, compiled);
        return (!is_secret_plausible(candidate, placeholder_keywords, plausibility_context))
            .then_some(StageId::EntropyValueShape(
                EntropyShapeStage::SecretPlausibilityRejected,
            ));
    }
    if !structured_dotted && candidate.len() < keyword_free_min_len.min(context.min_len) {
        return Some(StageId::EntropyValueShape(
            EntropyShapeStage::KeywordFreeTooShort,
        ));
    }
    let plausibility_context =
        PlausibilityContext::from_compiled(context.is_credential_context, false, compiled);
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

/// Resolve a testing context through the embedded compiled detector policy.
pub(crate) fn keyword_context(
    keyword_line: &str,
    min_length: usize,
    entropy_threshold: f64,
    secret_keywords: &[String],
) -> KeywordContext {
    match keyword_context_with_policy(
        keyword_line,
        min_length,
        entropy_threshold,
        secret_keywords,
        None,
    ) {
        Some(context) => context,
        None => panic!(
            "embedded detector entropy policy is unavailable for the supplied keyword context; fix the owning detector TOML"
        ),
    }
}

fn keyword_context_with_policy(
    keyword_line: &str,
    min_length: usize,
    entropy_threshold: f64,
    secret_keywords: &[String],
    active_policy: Option<ActiveDetectorPolicy<'_>>,
) -> Option<KeywordContext> {
    let line_bytes = keyword_line.as_bytes();
    let exact_assignment_keyword =
        crate::entropy::keywords::assignment_keyword_for_line(keyword_line);
    let keyword = exact_assignment_keyword.as_deref().or_else(|| {
        secret_keywords
            .iter()
            .find(|keyword| crate::ascii_ci::ci_find_nonempty(line_bytes, keyword.as_bytes()))
            .map(|keyword| keyword.as_str())
    })?;
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

    let compiled = get_compiled_policy_for_keyword(active_policy, keyword)?;
    let entropy_low = compiled.entropy_low;
    let min_len = compiled.min_len;
    let entropy_high = compiled.entropy_high;

    // Keyword-anchored floor policy (a NAMED, tested rule, not a silent clamp).
    // Inside a credential-keyword context the keyword IS the positive evidence,
    // so the entropy bar is the LOW floor. The operator's Tier-A threshold
    // engages only when it is stricter than this detector's compiled HIGH floor.
    // It is honored verbatim when it overrides; otherwise the keyword floor is
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
        plausibility_policy: *compiled,
    })
}
