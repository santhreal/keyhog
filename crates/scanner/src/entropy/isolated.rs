#[cfg(feature = "entropy")]
use super::keywords::is_likely_innocuous_line;
use super::keywords::KeywordContext;
use super::plausibility::is_isolated_bare_secret_plausible;
use super::{
    operator_entropy_override, shannon_entropy, EntropyMatch, FIRST_SOURCE_LINE_NUMBER,
    ISOLATED_BARE_ENTROPY_LABEL,
};
use crate::adjudicate::{EntropyShapeStage, StageId};

#[derive(Clone, Copy)]
struct IsolatedCandidatePolicy {
    mixed_entropy_floor: f64,
    mixed_min_len: usize,
    symbolic_entropy_floor: f64,
    symbolic_min_len: usize,
    symbolic_min_symbols: usize,
    symbolic_requires_non_underscore: bool,
    colon_left_min_len: usize,
    colon_right_min_len: usize,
}

impl IsolatedCandidatePolicy {
    fn from_compiled(policy: &super::policy::CompiledEntropyPolicy) -> Self {
        Self {
            mixed_entropy_floor: policy.isolated_mixed_entropy_floor,
            mixed_min_len: policy.keyword_free_min_len,
            symbolic_entropy_floor: policy.symbolic_entropy_floor,
            symbolic_min_len: policy.isolated_symbolic_min_len,
            symbolic_min_symbols: policy.isolated_symbolic_min_symbols,
            symbolic_requires_non_underscore: policy.isolated_symbolic_requires_non_underscore,
            colon_left_min_len: policy.isolated_colon_left_min_len,
            colon_right_min_len: policy.isolated_colon_right_min_len,
        }
    }

    /// Convenience entropy entry points do not carry a compiled scanner, so
    /// they compile the same embedded detector policy once instead of reading
    /// flexible schema fields or owning scanner constants.
    fn from_embedded_detector() -> Self {
        static POLICY: std::sync::LazyLock<IsolatedCandidatePolicy> =
            std::sync::LazyLock::new(|| {
                let detector = keyhog_core::embedded_detector_specs()
                    .iter()
                    .find(|detector| {
                        detector
                            .entropy_roles
                            .contains(&keyhog_core::EntropyDetectionRole::IsolatedBare)
                    })
                    .expect(
                        "embedded detector corpus must declare one isolated-bare entropy owner",
                    );
                let compiled = match super::policy::CompiledEntropyPolicy::compile(detector) {
                    Ok(policy) => policy,
                    Err(error) => {
                        panic!("embedded isolated-bare entropy policy is invalid: {error}")
                    }
                };
                IsolatedCandidatePolicy::from_compiled(&compiled)
            });
        *POLICY
    }

    #[inline]
    fn resolve(policy: Option<&super::policy::CompiledEntropyPolicy>) -> Self {
        match policy {
            Some(policy) => Self::from_compiled(policy),
            None => Self::from_embedded_detector(),
        }
    }
}

#[cfg(feature = "entropy")]
pub(crate) fn has_isolated_bare_secret_candidate_with_policy(
    text: &str,
    entropy_threshold: f64,
    placeholder_keywords: &[String],
    min_len: usize,
    entropy_shape: Option<keyhog_core::EntropyShapeSpec>,
    plausibility_policy: Option<super::policy::CompiledEntropyPolicy>,
) -> bool {
    // Stream `text.lines()` straight into `.any()` instead of collecting a
    // `Vec<&str>` first (Law 7: this runs twice per coalesced chunk in
    // scan_coalesced.rs, the temporary line vector was a pure per-call
    // allocation). `text.lines()` yields exactly the same `&str` sequence the
    // collected slice did, so this is byte-for-byte equivalent.
    let candidate_policy = IsolatedCandidatePolicy::resolve(plausibility_policy.as_ref());
    let threshold = isolated_bare_entropy_threshold(entropy_threshold, candidate_policy);
    text.lines().any(|line| {
        line_has_isolated_bare_secret_candidate(
            line,
            threshold,
            placeholder_keywords,
            min_len,
            entropy_shape,
            plausibility_policy,
        )
    })
}

#[cfg(feature = "entropy")]
pub(crate) fn has_isolated_bare_secret_candidate_with_lines_and_policy(
    lines: &[&str],
    entropy_threshold: f64,
    placeholder_keywords: &[String],
    min_len: usize,
    entropy_shape: Option<keyhog_core::EntropyShapeSpec>,
    plausibility_policy: Option<super::policy::CompiledEntropyPolicy>,
) -> bool {
    let candidate_policy = IsolatedCandidatePolicy::resolve(plausibility_policy.as_ref());
    let threshold = isolated_bare_entropy_threshold(entropy_threshold, candidate_policy);
    lines.iter().any(|line| {
        line_has_isolated_bare_secret_candidate(
            line,
            threshold,
            placeholder_keywords,
            min_len,
            entropy_shape,
            plausibility_policy,
        )
    })
}

/// Per-line predicate shared by the `&str` and `&[&str]` entry points so the
/// innocuous-line skip + candidate-visit logic has one definition. `threshold`
/// is already resolved by [`isolated_bare_entropy_threshold`] at the caller.
#[cfg(feature = "entropy")]
fn line_has_isolated_bare_secret_candidate(
    line: &str,
    threshold: f64,
    placeholder_keywords: &[String],
    min_len: usize,
    entropy_shape: Option<keyhog_core::EntropyShapeSpec>,
    plausibility_policy: Option<super::policy::CompiledEntropyPolicy>,
) -> bool {
    if is_likely_innocuous_line(line) {
        return false;
    }
    let candidate_policy = IsolatedCandidatePolicy::resolve(plausibility_policy.as_ref());
    let mut found = false;
    visit_isolated_bare_candidates(line, min_len.max(1), candidate_policy, |candidate, _| {
        found |= isolated_bare_secret_entropy(
            candidate,
            threshold,
            placeholder_keywords,
            entropy_shape,
            plausibility_policy,
        )
        .is_some();
    });
    // Generic detector TOMLs keep their broad keyword-free floor at 20 bytes,
    // but narrower symbolic/app-password shapes have stronger shape proof down
    // to 16 bytes. Revisit only that special band; ordinary tokens continue to
    // obey the detector-owned broad minimum.
    let special_min_len =
        isolated_special_shape_min_len(entropy_shape.as_ref(), plausibility_policy.as_ref());
    if !found && min_len > special_min_len {
        visit_isolated_bare_candidates(line, special_min_len, candidate_policy, |candidate, _| {
            if !isolated_special_shape_possible(candidate, entropy_shape.as_ref(), candidate_policy)
            {
                return;
            }
            let entropy = shannon_entropy(candidate.as_bytes());
            if isolated_special_shape_floor_met(
                candidate,
                entropy,
                entropy_shape.as_ref(),
                candidate_policy,
            ) {
                found |= isolated_bare_secret_entropy(
                    candidate,
                    threshold,
                    placeholder_keywords,
                    entropy_shape,
                    plausibility_policy,
                )
                .is_some();
            }
        });
    }
    found
}

/// The isolated-bare floor comes from its detector's mixed-alphanumeric policy
/// unless the operator's Tier-A threshold is stricter, in which case the shared
/// override rule wins. Scanner code owns the resolution rule, never the value.
fn isolated_bare_entropy_threshold(
    entropy_threshold: f64,
    candidate_policy: IsolatedCandidatePolicy,
) -> f64 {
    operator_entropy_override(entropy_threshold)
        .map_or(candidate_policy.mixed_entropy_floor, |threshold| threshold)
}

fn isolated_bare_entropy_floor_met(
    candidate: &str,
    entropy: f64,
    threshold: f64,
    shape_policy: Option<&keyhog_core::EntropyShapeSpec>,
    candidate_policy: IsolatedCandidatePolicy,
) -> bool {
    if entropy >= threshold {
        return true;
    }
    if threshold > candidate_policy.mixed_entropy_floor {
        return false;
    }
    mixed_separator_token_floor_met(
        candidate,
        entropy,
        candidate_policy.mixed_entropy_floor,
        candidate_policy.mixed_min_len,
    ) || lower_dash_app_password_floor_met_with_policy(candidate, entropy, shape_policy)
        || mixed_contiguous_token_floor_met(
            candidate,
            entropy,
            candidate_policy.mixed_entropy_floor,
            candidate_policy.mixed_min_len,
        )
        || isolated_special_shape_floor_met(candidate, entropy, shape_policy, candidate_policy)
}

pub(super) fn isolated_bare_keyword_context_with_shape(
    entropy_threshold: f64,
    min_len: usize,
    entropy_shape: Option<keyhog_core::EntropyShapeSpec>,
    plausibility_policy: Option<super::policy::CompiledEntropyPolicy>,
) -> KeywordContext {
    let candidate_policy = IsolatedCandidatePolicy::resolve(plausibility_policy.as_ref());
    KeywordContext {
        keyword: ISOLATED_BARE_ENTROPY_LABEL.to_string(),
        threshold: isolated_bare_entropy_threshold(entropy_threshold, candidate_policy),
        min_len: min_len.max(1),
        is_credential_context: false,
        entropy_shape,
        plausibility_policy,
    }
}

pub(crate) fn mixed_separator_token_floor_met(
    candidate: &str,
    entropy: f64,
    entropy_floor: f64,
    min_len: usize,
) -> bool {
    if entropy < entropy_floor || candidate.len() < min_len || !candidate.contains('_') {
        return false;
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    for b in candidate.bytes() {
        if b == b'_' {
            continue;
        }
        if !b.is_ascii_alphanumeric() {
            return false;
        }
        has_upper |= b.is_ascii_uppercase();
        has_lower |= b.is_ascii_lowercase();
        has_digit |= b.is_ascii_digit();
    }
    has_upper && has_lower && has_digit
}

pub(super) fn isolated_special_shape_min_len(
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
    policy: Option<&super::policy::CompiledEntropyPolicy>,
) -> usize {
    let candidate_policy = IsolatedCandidatePolicy::resolve(policy);
    entropy_shape
        .and_then(|shape| match shape {
            keyhog_core::EntropyShapeSpec::LowerDashAppPassword {
                special_min_length, ..
            } => Some(*special_min_length),
        })
        .map_or(candidate_policy.symbolic_min_len, |min_len| {
            min_len.min(candidate_policy.symbolic_min_len)
        })
}

fn isolated_special_shape_floor_met(
    candidate: &str,
    entropy: f64,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
    candidate_policy: IsolatedCandidatePolicy,
) -> bool {
    if lower_dash_app_password_layout_matches(candidate, entropy_shape) {
        return lower_dash_app_password_floor_met_with_policy(candidate, entropy, entropy_shape);
    }
    entropy >= candidate_policy.symbolic_entropy_floor
        && symbolic_special_shape_candidate(candidate, candidate_policy)
}

fn isolated_special_shape_possible(
    candidate: &str,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
    candidate_policy: IsolatedCandidatePolicy,
) -> bool {
    if lower_dash_app_password_layout_matches(candidate, entropy_shape) {
        return lower_dash_app_password_shape_matches(candidate, entropy_shape);
    }
    symbolic_special_shape_candidate(candidate, candidate_policy)
}

fn symbolic_special_shape_candidate(
    candidate: &str,
    candidate_policy: IsolatedCandidatePolicy,
) -> bool {
    if candidate.len() < candidate_policy.symbolic_min_len || candidate.contains("://") {
        return false;
    }
    let mut has_alpha = false;
    let mut has_digit = false;
    let mut symbols = 0usize;
    let mut has_non_underscore_symbol = false;
    for byte in candidate.bytes() {
        if byte.is_ascii_alphabetic() {
            has_alpha = true;
        } else if byte.is_ascii_digit() {
            has_digit = true;
        } else if matches!(
            byte,
            b'-' | b'_'
                | b'+'
                | b'/'
                | b'='
                | b'.'
                | b'!'
                | b'@'
                | b'#'
                | b'$'
                | b'%'
                | b'^'
                | b'&'
                | b'*'
        ) {
            symbols += 1;
            has_non_underscore_symbol |= byte != b'_';
        } else {
            return false;
        }
    }
    has_alpha
        && symbols >= candidate_policy.symbolic_min_symbols
        && (!candidate_policy.symbolic_requires_non_underscore || has_non_underscore_symbol)
        && (has_digit
            || symbolic_alpha_only_opaque_candidate(candidate, candidate_policy.symbolic_min_len))
}

pub(super) fn isolated_special_shape_floor_met_with_policy(
    candidate: &str,
    entropy: f64,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
    policy: Option<&super::policy::CompiledEntropyPolicy>,
) -> bool {
    isolated_special_shape_floor_met(
        candidate,
        entropy,
        entropy_shape,
        IsolatedCandidatePolicy::resolve(policy),
    )
}

pub(crate) fn lower_dash_app_password_floor_met_with_policy(
    candidate: &str,
    entropy: f64,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
) -> bool {
    let Some(entropy_floor) = lower_dash_app_password_declared_floor(entropy_shape) else {
        return false;
    };
    entropy >= entropy_floor && lower_dash_app_password_shape_matches(candidate, entropy_shape)
}

fn lower_dash_app_password_declared_floor(
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
) -> Option<f64> {
    let Some(keyhog_core::EntropyShapeSpec::LowerDashAppPassword { entropy_floor, .. }) =
        entropy_shape
    else {
        return None;
    };
    Some(*entropy_floor)
}

fn lower_dash_app_password_shape_matches(
    candidate: &str,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
) -> bool {
    if !lower_dash_app_password_layout_matches(candidate, entropy_shape) {
        return false;
    }

    let mut has_non_hex = false;
    for group in candidate.split('-') {
        let mut has_alpha = false;
        let mut has_digit = false;
        for b in group.bytes() {
            if !(b.is_ascii_lowercase() || b.is_ascii_digit()) {
                return false;
            }
            has_alpha |= b.is_ascii_lowercase();
            has_digit |= b.is_ascii_digit();
            has_non_hex |= b.is_ascii_alphabetic() && !b.is_ascii_hexdigit();
        }
        if !has_alpha || !has_digit {
            return false;
        }
    }

    has_non_hex
}

fn lower_dash_app_password_layout_matches(
    candidate: &str,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
) -> bool {
    let Some(keyhog_core::EntropyShapeSpec::LowerDashAppPassword {
        group_count,
        group_length,
        ..
    }) = entropy_shape
    else {
        return false;
    };
    let Some(expected_len) = group_count
        .checked_mul(*group_length)
        .and_then(|length| length.checked_add(group_count.saturating_sub(1)))
    else {
        return false;
    };
    if candidate.len() != expected_len {
        return false;
    }
    let mut actual_groups = 0usize;
    for group in candidate.split('-') {
        if group.len() != *group_length {
            return false;
        }
        actual_groups += 1;
    }
    actual_groups == *group_count
}

pub(crate) fn mixed_contiguous_token_floor_met(
    candidate: &str,
    entropy: f64,
    entropy_floor: f64,
    min_len: usize,
) -> bool {
    if entropy < entropy_floor || candidate.len() < min_len {
        return false;
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut all_hex = true;
    for b in candidate.bytes() {
        if !b.is_ascii_alphanumeric() {
            return false;
        }
        has_upper |= b.is_ascii_uppercase();
        has_lower |= b.is_ascii_lowercase();
        has_digit |= b.is_ascii_digit();
        all_hex &= b.is_ascii_hexdigit();
    }
    has_upper
        && has_lower
        && has_digit
        && !all_hex
        && crate::suppression::token_randomness::is_random_token(candidate)
}

/// Inner extraction logic without the `is_likely_innocuous_line` gate.
/// The caller MUST have already verified the line is not innocuous.
/// Used by `scan_keyword_free_candidates` which performs the innocuous check
/// once per line for both the isolated-bare and line-candidate paths.
pub(super) fn collect_isolated_bare_candidates_inner(
    line: &str,
    line_idx: usize,
    line_offset: usize,
    context: &KeywordContext,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
    placeholder_keywords: &[String],
) {
    let mut emit_candidate = |candidate: &str, candidate_offset: usize| {
        let entropy = match isolated_bare_secret_entropy_decision(
            candidate,
            context.threshold,
            placeholder_keywords,
            context.entropy_shape,
            context.plausibility_policy,
        ) {
            Ok(entropy) => entropy,
            Err(stage_id) => {
                if crate::telemetry::is_dogfood_enabled() {
                    let ctx = crate::adjudicate::MatchCtx::for_entropy_generation(
                        crate::adjudicate::EntropyGenerationSignal::SuppressionStage(stage_id),
                    );
                    crate::adjudicate::record_suppression(None, candidate, &ctx);
                }
                return;
            }
        };
        if seen.contains(candidate) {
            return;
        }
        seen.insert(candidate.to_string());
        matches.push(EntropyMatch {
            value: candidate.to_string(),
            entropy,
            keyword: context.keyword.clone(),
            line: line_idx + FIRST_SOURCE_LINE_NUMBER,
            offset: line_offset + candidate_offset,
        });
    };
    let candidate_policy = IsolatedCandidatePolicy::resolve(context.plausibility_policy.as_ref());
    visit_isolated_bare_candidates(line, context.min_len, candidate_policy, &mut emit_candidate);
    // See the matching admission exception in
    // `line_has_isolated_bare_secret_candidate`: only shape-proven symbolic or
    // 4x4 app-password candidates may cross a broader detector TOML floor.
    let special_min_len = isolated_special_shape_min_len(
        context.entropy_shape.as_ref(),
        context.plausibility_policy.as_ref(),
    );
    if context.min_len > special_min_len {
        visit_isolated_bare_candidates(
            line,
            special_min_len,
            candidate_policy,
            |candidate, candidate_offset| {
                if candidate.len() >= context.min_len
                    || !isolated_special_shape_possible(
                        candidate,
                        context.entropy_shape.as_ref(),
                        candidate_policy,
                    )
                {
                    return;
                }
                let entropy = shannon_entropy(candidate.as_bytes());
                if isolated_special_shape_floor_met(
                    candidate,
                    entropy,
                    context.entropy_shape.as_ref(),
                    candidate_policy,
                ) {
                    emit_candidate(candidate, candidate_offset);
                }
            },
        );
    }
}

#[cfg(feature = "entropy")]
fn isolated_bare_secret_entropy(
    candidate: &str,
    threshold: f64,
    placeholder_keywords: &[String],
    entropy_shape: Option<keyhog_core::EntropyShapeSpec>,
    plausibility_policy: Option<super::policy::CompiledEntropyPolicy>,
) -> Option<f64> {
    match isolated_bare_secret_entropy_decision(
        candidate,
        threshold,
        placeholder_keywords,
        entropy_shape,
        plausibility_policy,
    ) {
        Ok(entropy) => Some(entropy),
        Err(_stage) => {
            // Boolean-predicate adapter: a rejection is simply "not an isolated
            // bare secret" (None/false). The emit path calls the Result-returning
            // decision helper directly and records the typed adjudication stage.
            None
        }
    }
}

fn isolated_bare_secret_entropy_decision(
    candidate: &str,
    threshold: f64,
    placeholder_keywords: &[String],
    entropy_shape: Option<keyhog_core::EntropyShapeSpec>,
    plausibility_policy: Option<super::policy::CompiledEntropyPolicy>,
) -> Result<f64, StageId> {
    if super::scanner::is_canonical_non_secret_shape(candidate) {
        return Err(StageId::EntropyValueShape(
            EntropyShapeStage::CanonicalNonSecretShape,
        ));
    }
    let entropy = shannon_entropy(candidate.as_bytes());
    if !isolated_bare_entropy_floor_met(
        candidate,
        entropy,
        threshold,
        entropy_shape.as_ref(),
        IsolatedCandidatePolicy::resolve(plausibility_policy.as_ref()),
    ) {
        return Err(StageId::EntropyBelowFloor);
    }
    if !is_isolated_bare_secret_plausible(
        candidate,
        placeholder_keywords,
        entropy_shape,
        plausibility_policy,
    ) {
        return Err(StageId::EntropyValueShape(
            EntropyShapeStage::SecretPlausibilityRejected,
        ));
    }
    Ok(entropy)
}

fn visit_isolated_bare_candidates<'a>(
    line: &'a str,
    min_len: usize,
    candidate_policy: IsolatedCandidatePolicy,
    mut visit: impl FnMut(&'a str, usize),
) {
    // Check whitespace before the full-line candidate path. Multi-word source
    // lines cannot be isolated bare candidates, so they proceed directly to
    // bounded per-token scanning without repeated full-line trimming.
    let bytes = line.as_bytes();
    let has_whitespace = bytes.iter().any(|&b| b.is_ascii_whitespace());
    if !has_whitespace {
        if let Some(candidate) = isolated_bare_candidate(line, min_len, candidate_policy) {
            // SAFETY: `candidate` is returned by `isolated_bare_candidate(line, ...)`,
            // which derives it solely from `line.trim().trim_matches(...)`. Both `trim`
            // operations return subslices of `line`, so `candidate.as_ptr() >= line.as_ptr()`
            // is guaranteed by the standard library's trim contract; subtraction cannot wrap.
            let candidate_offset = candidate.as_ptr() as usize - line.as_ptr() as usize;
            visit(candidate, candidate_offset);
        }
        return;
    }

    let mut cursor = 0usize;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let token_start = cursor;
        while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let token_end = cursor;
        if token_start == token_end {
            continue;
        }
        if let Some((candidate, candidate_offset)) =
            isolated_bare_candidate_in_span(line, token_start, token_end, min_len, candidate_policy)
        {
            visit(candidate, candidate_offset);
        }
    }
}

fn isolated_bare_candidate_in_span(
    line: &str,
    token_start: usize,
    token_end: usize,
    min_len: usize,
    candidate_policy: IsolatedCandidatePolicy,
) -> Option<(&str, usize)> {
    let token_len = token_end - token_start;
    // Fast length reject: even without stripping `;`/`,`, if the token is
    // shorter than min_len, no candidate from it can pass. This saves the
    // leading/trailing strip + `isolated_bare_candidate` call for short tokens.
    if token_len < min_len {
        return None;
    }
    let token = &line[token_start..token_end];
    let leading = token
        .bytes()
        .take_while(|b| matches!(*b, b';' | b','))
        .count();
    let trailing = token
        .bytes()
        .rev()
        .take_while(|b| matches!(*b, b';' | b','))
        .count();
    if leading + trailing >= token.len() {
        return None;
    }
    let candidate_start = token_start + leading;
    let candidate_end = token_end - trailing;
    let candidate = &line[candidate_start..candidate_end];
    // Per-token entropy-run prefilter using the same lookup table as the
    // per-line scan in `scan_keyword_free_candidates`. A real secret of length
    // ≥ min_len consists almost entirely of entropy candidate bytes. If the
    // longest such run in the candidate is < min_len, skip the expensive
    // `isolated_bare_candidate` + Shannon entropy computation.
    //
    // This is the key optimization for source-code filler: tokens like
    // `compute_value(42)` (17 chars) have `(` and `)` breaking the entropy run,
    // giving max_entropy_run = 13 (`compute_value`), which is < 16. Without
    // this check, `symbolic_isolated_bare_candidate` would accept it (2
    // non-alphanumeric graphic chars ≥ 2), and the full Shannon entropy
    // computation would run (only to reject it for low entropy).
    let mut max_ent_run = 0usize;
    let mut cur_ent_run = 0usize;
    for &b in candidate.as_bytes() {
        if super::scanner::BYTE_CLASS[b as usize] & 2 != 0 {
            cur_ent_run += 1;
            if cur_ent_run > max_ent_run {
                max_ent_run = cur_ent_run;
            }
        } else {
            cur_ent_run = 0;
        }
    }
    if max_ent_run < min_len {
        return None;
    }
    isolated_bare_candidate(candidate, min_len, candidate_policy).map(|value| {
        // SAFETY: `value` is a subslice of `candidate` (via str::trim/trim_matches inside
        // `isolated_bare_candidate`), and `candidate` is `&line[candidate_start..candidate_end]`
        // a direct subslice of `line`. Therefore `value.as_ptr() >= line.as_ptr()` is
        // guaranteed; subtraction cannot underflow.
        let offset = value.as_ptr() as usize - line.as_ptr() as usize;
        (value, offset)
    })
}

fn isolated_bare_candidate(
    line: &str,
    min_len: usize,
    candidate_policy: IsolatedCandidatePolicy,
) -> Option<&str> {
    let candidate = line.trim().trim_matches(|c: char| c == ';' || c == ',');
    if candidate.len() < min_len || candidate.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    let has_alpha = candidate.bytes().any(|b| b.is_ascii_alphabetic());
    let has_digit = candidate.bytes().any(|b| b.is_ascii_digit());
    let no_digit_symbolic_token = !has_digit
        && symbolic_alpha_only_opaque_candidate(candidate, candidate_policy.symbolic_min_len);
    if !has_alpha || (!has_digit && !no_digit_symbolic_token) {
        return None;
    }
    let has_assignment_equals = crate::decode::contains_non_padding_equals(candidate);
    let standard_token = !candidate.contains("://")
        && !has_assignment_equals
        && !candidate.contains('<')
        && !candidate.contains('>')
        && candidate.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_'
                        | b'+'
                        | b'/'
                        | b'='
                        | b'.'
                        | b'!'
                        | b'@'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'^'
                        | b'&'
                        | b'*'
                )
        });
    let bang_led_symbolic_token = has_assignment_equals
        && candidate.starts_with('!')
        && !candidate.starts_with("!!")
        && symbolic_isolated_bare_candidate(candidate);
    if standard_token
        || colon_separated_opaque_candidate(
            candidate,
            candidate_policy.colon_left_min_len,
            candidate_policy.colon_right_min_len,
        )
        || no_digit_symbolic_token
        || (!has_assignment_equals && symbolic_isolated_bare_candidate(candidate))
        || bang_led_symbolic_token
    {
        return Some(candidate);
    }
    None
}

pub(crate) fn colon_separated_opaque_candidate(
    candidate: &str,
    left_min_len: usize,
    right_min_len: usize,
) -> bool {
    if candidate.contains("://") || candidate.bytes().filter(|&b| b == b':').count() != 1 {
        return false;
    }
    let Some((left, right)) = candidate.split_once(':') else {
        return false;
    };
    if left.len() < left_min_len || right.len() < right_min_len {
        return false;
    }
    [left, right].into_iter().all(|part| {
        let mut has_alpha = false;
        let mut has_digit = false;
        for b in part.bytes() {
            if !b.is_ascii_alphanumeric() {
                return false;
            }
            has_alpha |= b.is_ascii_alphabetic();
            has_digit |= b.is_ascii_digit();
        }
        has_alpha && has_digit
    })
}

pub(crate) fn symbolic_alpha_only_opaque_candidate(candidate: &str, min_len: usize) -> bool {
    if candidate.len() < min_len || candidate.contains("://") {
        return false;
    }
    let mut has_upper = false;
    let mut has_lower = false;
    let mut alpha = 0usize;
    let mut punctuation = 0usize;
    for b in candidate.bytes() {
        if !b.is_ascii_graphic() || matches!(b, b'"' | b'\'' | b'`') {
            return false;
        }
        if b.is_ascii_digit() {
            return false;
        }
        if b.is_ascii_alphabetic() {
            alpha += 1;
            has_upper |= b.is_ascii_uppercase();
            has_lower |= b.is_ascii_lowercase();
        } else {
            punctuation += 1;
        }
    }
    has_upper
        && has_lower
        && punctuation >= 3
        && alpha * 2 >= candidate.len()
        && crate::suppression::token_randomness::is_random_token(candidate)
}

pub(crate) fn symbolic_isolated_bare_candidate(candidate: &str) -> bool {
    if candidate.contains("://") || candidate.bytes().any(|b| matches!(b, b':' | b',')) {
        return false;
    }
    let mut symbol_count = 0usize;
    for b in candidate.bytes() {
        if matches!(b, b'"' | b'\'' | b'`') || !b.is_ascii_graphic() {
            return false;
        }
        if !b.is_ascii_alphanumeric() {
            symbol_count += 1;
        }
    }
    symbol_count >= 2
}

#[cfg(test)]
mod threshold_tests {
    use super::{isolated_bare_entropy_threshold, IsolatedCandidatePolicy};
    use crate::entropy::HIGH_ENTROPY_THRESHOLD;

    /// The detector-owned mixed floor wins for ordinary and non-finite Tier-A
    /// values; only a threshold strictly above the high floor overrides it.
    #[test]
    fn isolated_floor_uses_detector_policy_and_overrides_only_above_high() {
        let policy = IsolatedCandidatePolicy {
            mixed_entropy_floor: 3.7,
            mixed_min_len: 20,
            symbolic_entropy_floor: 3.5,
            symbolic_min_len: 18,
            symbolic_min_symbols: 2,
            symbolic_requires_non_underscore: true,
            colon_left_min_len: 20,
            colon_right_min_len: 16,
        };
        assert_eq!(
            isolated_bare_entropy_threshold(HIGH_ENTROPY_THRESHOLD, policy),
            3.7
        );
        assert_eq!(isolated_bare_entropy_threshold(4.0, policy), 3.7);
        assert_eq!(isolated_bare_entropy_threshold(2.0, policy), 3.7);
        assert_eq!(isolated_bare_entropy_threshold(f64::NAN, policy), 3.7);
        assert_eq!(isolated_bare_entropy_threshold(5.8, policy), 5.8);
        assert_eq!(isolated_bare_entropy_threshold(8.0, policy), 8.0);
    }
}
