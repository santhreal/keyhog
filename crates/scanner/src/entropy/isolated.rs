#[cfg(feature = "entropy")]
use super::keywords::is_likely_innocuous_line;
use super::keywords::KeywordContext;
use super::plausibility::is_isolated_bare_secret_plausible;
use super::{
    shannon_entropy, ClassifiedEntropyMatch, EntropyMatch, FIRST_SOURCE_LINE_NUMBER,
    ISOLATED_BARE_ENTROPY_LABEL,
};
use crate::adjudicate::{EntropyShapeStage, StageId};

#[derive(Clone, Copy)]
struct IsolatedCandidatePolicy {
    entropy_high: f64,
    mixed_entropy_floor: f64,
    mixed_min_len: usize,
    symbolic_entropy_floor: f64,
    symbolic_min_len: usize,
    symbolic_min_symbols: usize,
    symbolic_requires_non_underscore: bool,
    alpha_only_min_symbols: usize,
    alpha_only_min_alpha_ratio: f64,
    colon_left_min_len: usize,
    colon_right_min_len: usize,
}

impl IsolatedCandidatePolicy {
    fn from_compiled(policy: &super::policy::CompiledEntropyPolicy) -> Self {
        Self {
            entropy_high: policy.entropy_high,
            mixed_entropy_floor: policy.isolated_mixed_entropy_floor,
            mixed_min_len: policy.keyword_free_min_len,
            symbolic_entropy_floor: policy.symbolic_entropy_floor,
            symbolic_min_len: policy.isolated_symbolic_min_len,
            symbolic_min_symbols: policy.isolated_symbolic_min_symbols,
            symbolic_requires_non_underscore: policy.isolated_symbolic_requires_non_underscore,
            alpha_only_min_symbols: policy.isolated_alpha_only_min_symbols,
            alpha_only_min_alpha_ratio: policy.isolated_alpha_only_min_alpha_ratio,
            colon_left_min_len: policy.isolated_colon_left_min_len,
            colon_right_min_len: policy.isolated_colon_right_min_len,
        }
    }
}

#[cfg(feature = "entropy")]
pub(crate) fn has_isolated_bare_secret_candidate_with_policy(
    text: &str,
    entropy_threshold: f64,
    placeholder_keywords: &[String],
    min_len: usize,
    plausibility_policy: &super::policy::CompiledEntropyPolicy,
) -> bool {
    // Stream `text.lines()` straight into `.any()` instead of collecting a
    // `Vec<&str>` first (Law 7: this runs twice per coalesced chunk in
    // scan_coalesced.rs, the temporary line vector was a pure per-call
    // allocation). `text.lines()` yields exactly the same `&str` sequence the
    // collected slice did, so this is byte-for-byte equivalent.
    let candidate_policy = IsolatedCandidatePolicy::from_compiled(plausibility_policy);
    let threshold = isolated_bare_entropy_threshold(entropy_threshold, candidate_policy);
    text.lines().any(|line| {
        line_has_isolated_bare_secret_candidate(
            line,
            threshold,
            placeholder_keywords,
            min_len,
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
    plausibility_policy: &super::policy::CompiledEntropyPolicy,
) -> bool {
    let candidate_policy = IsolatedCandidatePolicy::from_compiled(plausibility_policy);
    let threshold = isolated_bare_entropy_threshold(entropy_threshold, candidate_policy);
    lines.iter().any(|line| {
        line_has_isolated_bare_secret_candidate(
            line,
            threshold,
            placeholder_keywords,
            min_len,
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
    plausibility_policy: &super::policy::CompiledEntropyPolicy,
) -> bool {
    if is_likely_innocuous_line(line) {
        return false;
    }
    let entropy_shape = plausibility_policy.entropy_shape;
    let candidate_policy = IsolatedCandidatePolicy::from_compiled(plausibility_policy);
    let mut found = false;
    visit_isolated_bare_candidates(line, min_len.max(1), candidate_policy, |candidate, _| {
        found |= isolated_bare_secret_entropy(
            candidate,
            threshold,
            placeholder_keywords,
            plausibility_policy,
        )
        .is_some();
    });
    // Generic detector TOMLs keep their broad keyword-free floor at 20 bytes,
    // but narrower symbolic/app-password shapes have stronger shape proof down
    // to 16 bytes. Revisit only that special band; ordinary tokens continue to
    // obey the detector-owned broad minimum.
    let special_min_len =
        isolated_special_shape_min_len(entropy_shape.as_ref(), plausibility_policy);
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
    if entropy_threshold.is_finite() && entropy_threshold > candidate_policy.entropy_high {
        entropy_threshold
    } else {
        candidate_policy.mixed_entropy_floor
    }
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

pub(super) fn isolated_bare_keyword_context(
    entropy_threshold: f64,
    min_len: usize,
    plausibility_policy: super::policy::CompiledEntropyPolicy,
) -> KeywordContext {
    let candidate_policy = IsolatedCandidatePolicy::from_compiled(&plausibility_policy);
    KeywordContext {
        keyword: ISOLATED_BARE_ENTROPY_LABEL.to_string(),
        threshold: isolated_bare_entropy_threshold(entropy_threshold, candidate_policy),
        min_len: min_len.max(1),
        is_credential_context: false,
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
    policy: &super::policy::CompiledEntropyPolicy,
) -> usize {
    let candidate_policy = IsolatedCandidatePolicy::from_compiled(policy);
    entropy_shape
        .map(|shape| shape.special_min_length)
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
    if declared_entropy_shape_matches(candidate, entropy_shape) {
        return declared_entropy_shape_floor_met(candidate, entropy, entropy_shape);
    }
    entropy >= candidate_policy.symbolic_entropy_floor
        && symbolic_special_shape_candidate(candidate, candidate_policy)
}

fn isolated_special_shape_possible(
    candidate: &str,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
    candidate_policy: IsolatedCandidatePolicy,
) -> bool {
    if declared_entropy_shape_matches(candidate, entropy_shape) {
        return true;
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
            || symbolic_alpha_only_opaque_candidate(
                candidate,
                candidate_policy.symbolic_min_len,
                candidate_policy.alpha_only_min_symbols,
                candidate_policy.alpha_only_min_alpha_ratio,
            ))
}

pub(super) fn isolated_special_shape_floor_met_with_policy(
    candidate: &str,
    entropy: f64,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
    policy: &super::policy::CompiledEntropyPolicy,
) -> bool {
    isolated_special_shape_floor_met(
        candidate,
        entropy,
        entropy_shape,
        IsolatedCandidatePolicy::from_compiled(policy),
    )
}

pub(crate) fn lower_dash_app_password_floor_met_with_policy(
    candidate: &str,
    entropy: f64,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
) -> bool {
    declared_entropy_shape_floor_met(candidate, entropy, entropy_shape)
}

fn declared_entropy_shape_floor_met(
    candidate: &str,
    entropy: f64,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
) -> bool {
    let Some(shape) = entropy_shape else {
        return false;
    };
    entropy >= shape.entropy_floor && declared_entropy_shape_matches(candidate, entropy_shape)
}

fn declared_entropy_shape_matches(
    candidate: &str,
    entropy_shape: Option<&keyhog_core::EntropyShapeSpec>,
) -> bool {
    let Some(shape) = entropy_shape else {
        return false;
    };
    if candidate.len() < shape.special_min_length {
        return false;
    }

    let grouping = shape.grouping;
    if grouping.is_none() && candidate.as_bytes().contains(&0) {
        return false;
    }
    if let Some(grouping) = grouping {
        let Some(expected_len) = grouping
            .group_count
            .checked_mul(grouping.group_length)
            .and_then(|length| {
                length.checked_add(
                    grouping
                        .group_count
                        .saturating_sub(1)
                        .saturating_mul(grouping.separator.len_utf8()),
                )
            })
        else {
            return false;
        };
        if candidate.len() != expected_len {
            return false;
        }
    }

    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    let mut has_non_hex_alpha = false;
    let mut symbols = 0usize;
    let mut actual_groups = 0usize;
    // NUL cannot pass any declared ASCII charset, so it is a zero-allocation
    // sentinel that makes an ungrouped candidate yield exactly one group.
    let separator = grouping.map_or('\0', |grouping| grouping.separator);
    for group in candidate.split(separator) {
        if grouping.is_some_and(|grouping| group.len() != grouping.group_length) {
            return false;
        }
        actual_groups += 1;
        let mut group_has_alpha = false;
        let mut group_has_digit = false;
        if shape.charset == keyhog_core::ShapeCharset::Base64Standard
            && !valid_standard_base64_group(group.as_bytes())
        {
            return false;
        }
        if shape.charset == keyhog_core::ShapeCharset::Base64Url && group.len() % 4 == 1 {
            return false;
        }
        for byte in group.bytes() {
            if !shape_charset_accepts(shape.charset, byte) {
                return false;
            }
            has_upper |= byte.is_ascii_uppercase();
            has_lower |= byte.is_ascii_lowercase();
            has_digit |= byte.is_ascii_digit();
            group_has_alpha |= byte.is_ascii_alphabetic();
            group_has_digit |= byte.is_ascii_digit();
            has_non_hex_alpha |= byte.is_ascii_alphabetic() && !byte.is_ascii_hexdigit();
            symbols += usize::from(!byte.is_ascii_alphanumeric());
        }
        if shape.require_group_alpha_digit && (!group_has_alpha || !group_has_digit) {
            return false;
        }
    }

    if let Some(grouping) = grouping {
        if actual_groups != grouping.group_count {
            return false;
        }
        symbols = symbols.saturating_add(grouping.group_count.saturating_sub(1));
    }

    (!shape.require_mixed_case || (has_upper && has_lower))
        && (!shape.require_digit || has_digit)
        && symbols >= shape.min_symbols
        && (!shape.require_non_hex_alpha || has_non_hex_alpha)
}

fn valid_standard_base64_group(group: &[u8]) -> bool {
    if group.len() % 4 == 1 {
        return false;
    }
    let Some(first_padding) = group.iter().position(|&byte| byte == b'=') else {
        return true;
    };
    let padding = group.len() - first_padding;
    padding <= 2 && group.len() % 4 == 0 && group[first_padding..].iter().all(|&byte| byte == b'=')
}

fn shape_charset_accepts(charset: keyhog_core::ShapeCharset, byte: u8) -> bool {
    match charset {
        keyhog_core::ShapeCharset::LowerAlnum => byte.is_ascii_lowercase() || byte.is_ascii_digit(),
        keyhog_core::ShapeCharset::Hex => byte.is_ascii_hexdigit(),
        keyhog_core::ShapeCharset::Base64Standard => {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
        }
        keyhog_core::ShapeCharset::Base64Url => {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
        }
    }
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
    matches: &mut Vec<ClassifiedEntropyMatch>,
    placeholder_keywords: &[String],
) {
    let mut emit_candidate = |candidate: &str, candidate_offset: usize| {
        let entropy = match isolated_bare_secret_entropy_decision(
            candidate,
            context.threshold,
            placeholder_keywords,
            &context.plausibility_policy,
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
        matches.push(ClassifiedEntropyMatch {
            matched: EntropyMatch {
                value: candidate.to_string(),
                entropy,
                keyword: context.keyword.clone(),
                line: line_idx + FIRST_SOURCE_LINE_NUMBER,
                offset: line_offset + candidate_offset,
            },
            is_credential_context: false,
            is_same_line_credential_context: false,
        });
    };
    let candidate_policy = IsolatedCandidatePolicy::from_compiled(&context.plausibility_policy);
    visit_isolated_bare_candidates(line, context.min_len, candidate_policy, &mut emit_candidate);
    // See the matching admission exception in
    // `line_has_isolated_bare_secret_candidate`: only shape-proven symbolic or
    // 4x4 app-password candidates may cross a broader detector TOML floor.
    let special_min_len = isolated_special_shape_min_len(
        context.plausibility_policy.entropy_shape.as_ref(),
        &context.plausibility_policy,
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
                        context.plausibility_policy.entropy_shape.as_ref(),
                        candidate_policy,
                    )
                {
                    return;
                }
                let entropy = shannon_entropy(candidate.as_bytes());
                if isolated_special_shape_floor_met(
                    candidate,
                    entropy,
                    context.plausibility_policy.entropy_shape.as_ref(),
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
    plausibility_policy: &super::policy::CompiledEntropyPolicy,
) -> Option<f64> {
    match isolated_bare_secret_entropy_decision(
        candidate,
        threshold,
        placeholder_keywords,
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
    plausibility_policy: &super::policy::CompiledEntropyPolicy,
) -> Result<f64, StageId> {
    if super::scanner::is_canonical_non_secret_shape(candidate) {
        return Err(StageId::EntropyValueShape(
            EntropyShapeStage::CanonicalNonSecretShape,
        ));
    }
    let entropy = shannon_entropy(candidate.as_bytes());
    let entropy_shape = plausibility_policy.entropy_shape;
    if !isolated_bare_entropy_floor_met(
        candidate,
        entropy,
        threshold,
        entropy_shape.as_ref(),
        IsolatedCandidatePolicy::from_compiled(plausibility_policy),
    ) {
        return Err(StageId::EntropyBelowFloor);
    }
    if !is_isolated_bare_secret_plausible(candidate, placeholder_keywords, plausibility_policy) {
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
        && symbolic_alpha_only_opaque_candidate(
            candidate,
            candidate_policy.symbolic_min_len,
            candidate_policy.alpha_only_min_symbols,
            candidate_policy.alpha_only_min_alpha_ratio,
        );
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
        && symbolic_isolated_bare_candidate(candidate, candidate_policy);
    if standard_token
        || colon_separated_opaque_candidate(
            candidate,
            candidate_policy.colon_left_min_len,
            candidate_policy.colon_right_min_len,
        )
        || no_digit_symbolic_token
        || (!has_assignment_equals && symbolic_isolated_bare_candidate(candidate, candidate_policy))
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

fn symbolic_alpha_only_opaque_candidate(
    candidate: &str,
    min_len: usize,
    min_symbols: usize,
    min_alpha_ratio: f64,
) -> bool {
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
        && punctuation >= min_symbols
        && (alpha as f64) >= (candidate.len() as f64) * min_alpha_ratio
        && crate::suppression::token_randomness::is_random_token(candidate)
}

pub(crate) fn symbolic_alpha_only_opaque_candidate_with_policy(
    candidate: &str,
    policy: &super::policy::CompiledEntropyPolicy,
) -> bool {
    let candidate_policy = IsolatedCandidatePolicy::from_compiled(policy);
    symbolic_alpha_only_opaque_candidate(
        candidate,
        candidate_policy.symbolic_min_len,
        candidate_policy.alpha_only_min_symbols,
        candidate_policy.alpha_only_min_alpha_ratio,
    )
}

fn symbolic_isolated_bare_candidate(
    candidate: &str,
    candidate_policy: IsolatedCandidatePolicy,
) -> bool {
    if candidate.contains("://") || candidate.bytes().any(|b| matches!(b, b':' | b',')) {
        return false;
    }
    let mut symbol_count = 0usize;
    let mut has_non_underscore_symbol = false;
    for b in candidate.bytes() {
        if matches!(b, b'"' | b'\'' | b'`') || !b.is_ascii_graphic() {
            return false;
        }
        if !b.is_ascii_alphanumeric() {
            symbol_count += 1;
            has_non_underscore_symbol |= b != b'_';
        }
    }
    symbol_count >= candidate_policy.symbolic_min_symbols
        && (!candidate_policy.symbolic_requires_non_underscore || has_non_underscore_symbol)
}

pub(crate) fn symbolic_isolated_bare_candidate_with_policy(
    candidate: &str,
    policy: &super::policy::CompiledEntropyPolicy,
) -> bool {
    symbolic_isolated_bare_candidate(candidate, IsolatedCandidatePolicy::from_compiled(policy))
}

#[cfg(test)]
mod threshold_tests {
    use super::{isolated_bare_entropy_threshold, IsolatedCandidatePolicy};
    /// The detector-owned mixed floor wins for ordinary and non-finite Tier-A
    /// values; only a threshold strictly above the high floor overrides it.
    #[test]
    fn isolated_floor_uses_detector_policy_and_overrides_only_above_high() {
        let policy = IsolatedCandidatePolicy {
            entropy_high: 4.7,
            mixed_entropy_floor: 3.7,
            mixed_min_len: 20,
            symbolic_entropy_floor: 3.5,
            symbolic_min_len: 18,
            symbolic_min_symbols: 2,
            symbolic_requires_non_underscore: true,
            alpha_only_min_symbols: 3,
            alpha_only_min_alpha_ratio: 0.5,
            colon_left_min_len: 20,
            colon_right_min_len: 16,
        };
        assert_eq!(isolated_bare_entropy_threshold(4.5, policy), 3.7);
        assert_eq!(isolated_bare_entropy_threshold(4.7, policy), 3.7);
        assert_eq!(isolated_bare_entropy_threshold(4.0, policy), 3.7);
        assert_eq!(isolated_bare_entropy_threshold(2.0, policy), 3.7);
        assert_eq!(isolated_bare_entropy_threshold(f64::NAN, policy), 3.7);
        assert_eq!(isolated_bare_entropy_threshold(4.8, policy), 4.8);
        assert_eq!(isolated_bare_entropy_threshold(8.0, policy), 8.0);
    }
}
