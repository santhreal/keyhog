use super::keywords::{is_likely_innocuous_line, KeywordContext};
use super::plausibility::is_isolated_bare_secret_plausible;
use super::{
    operator_entropy_override, shannon_entropy, EntropyMatch, FIRST_SOURCE_LINE_NUMBER,
    ISOLATED_BARE_ENTROPY_LABEL, KEYWORD_FREE_MIN_LEN, MIXED_ALNUM_TOKEN_THRESHOLD,
};
use crate::adjudicate::{EntropyShapeStage, StageId};

/// Shannon floor for a mixed-charset isolated token (separator-joined or
/// contiguous). Single owner for the value both mixed-token floor predicates
/// share; two byte-identical inline copies used to drift independently.
const MIXED_TOKEN_ENTROPY_FLOOR: f64 = 3.65;

/// Minimum length for a digit-free, symbol-bearing all-alpha opaque token
/// (`symbolic_alpha_only_opaque_candidate`). Named beside the other isolated
/// length floors instead of an inline literal so the shape gate has one owner.
const SYMBOLIC_ALPHA_ONLY_MIN_LEN: usize = 18;
/// Right-hand component of a colon-separated opaque token has a slightly shorter
/// floor than the global keyword-free minimum so `user:token` forms where token
/// is 16 characters can still pass.
const COLON_RIGHT_PART_MIN_LEN: usize = 16;

#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) fn has_isolated_bare_secret_candidate(
    text: &str,
    entropy_threshold: f64,
    placeholder_keywords: &[String],
    min_len: usize,
) -> bool {
    // Stream `text.lines()` straight into `.any()` instead of collecting a
    // `Vec<&str>` first (Law 7: this runs twice per coalesced chunk in
    // scan_coalesced.rs — the temporary line vector was a pure per-call
    // allocation). `text.lines()` yields exactly the same `&str` sequence the
    // collected slice did, so this is byte-for-byte equivalent.
    let threshold = isolated_bare_entropy_threshold(entropy_threshold);
    text.lines().any(|line| {
        line_has_isolated_bare_secret_candidate(line, threshold, placeholder_keywords, min_len)
    })
}

#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) fn has_isolated_bare_secret_candidate_with_lines(
    lines: &[&str],
    entropy_threshold: f64,
    placeholder_keywords: &[String],
    min_len: usize,
) -> bool {
    let threshold = isolated_bare_entropy_threshold(entropy_threshold);
    lines.iter().any(|line| {
        line_has_isolated_bare_secret_candidate(line, threshold, placeholder_keywords, min_len)
    })
}

/// Per-line predicate shared by the `&str` and `&[&str]` entry points so the
/// innocuous-line skip + candidate-visit logic has one definition. `threshold`
/// is already resolved by [`isolated_bare_entropy_threshold`] at the caller.
#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
fn line_has_isolated_bare_secret_candidate(
    line: &str,
    threshold: f64,
    placeholder_keywords: &[String],
    min_len: usize,
) -> bool {
    if is_likely_innocuous_line(line) {
        return false;
    }
    let mut found = false;
    visit_isolated_bare_candidates(line, min_len.max(1), |candidate, _| {
        found |= isolated_bare_secret_entropy(candidate, threshold, placeholder_keywords).is_some();
    });
    // Generic detector TOMLs keep their broad keyword-free floor at 20 bytes,
    // but narrower symbolic/app-password shapes have stronger shape proof down
    // to 16 bytes. Revisit only that special band; ordinary tokens continue to
    // obey the detector-owned broad minimum.
    if !found && min_len > ISOLATED_SPECIAL_SHAPE_MIN_LEN {
        visit_isolated_bare_candidates(line, ISOLATED_SPECIAL_SHAPE_MIN_LEN, |candidate, _| {
            let entropy = shannon_entropy(candidate.as_bytes());
            if isolated_special_shape_floor_met(candidate, entropy) {
                found |= isolated_bare_secret_entropy(candidate, threshold, placeholder_keywords)
                    .is_some();
            }
        });
    }
    found
}

/// The isolated-bare floor: an opaque anchor-free token runs at the
/// [`MIXED_ALNUM_TOKEN_THRESHOLD`] floor unless the operator's Tier-A threshold
/// is stricter than the blanket high floor, in which case the shared
/// [`operator_entropy_override`] owner honors it verbatim. One owner for the
/// `> HIGH` override decision, shared with `scanner::keyword_context` — the two
/// sites used to inline divergent copies of the same test.
fn isolated_bare_entropy_threshold(entropy_threshold: f64) -> f64 {
    operator_entropy_override(entropy_threshold)
        .map_or(MIXED_ALNUM_TOKEN_THRESHOLD, |threshold| threshold)
}

fn isolated_bare_entropy_floor_met(candidate: &str, entropy: f64, threshold: f64) -> bool {
    if entropy >= threshold {
        return true;
    }
    if threshold > MIXED_ALNUM_TOKEN_THRESHOLD {
        return false;
    }
    mixed_separator_token_floor_met(candidate, entropy)
        || lower_dash_app_password_floor_met(candidate, entropy)
        || mixed_contiguous_token_floor_met(candidate, entropy)
}

pub(super) fn isolated_bare_keyword_context(
    entropy_threshold: f64,
    min_len: usize,
) -> KeywordContext {
    KeywordContext {
        keyword: ISOLATED_BARE_ENTROPY_LABEL.to_string(),
        threshold: isolated_bare_entropy_threshold(entropy_threshold),
        min_len: min_len.max(1),
        is_credential_context: false,
        allow_canonical_shapes: false,
    }
}

pub(crate) fn mixed_separator_token_floor_met(candidate: &str, entropy: f64) -> bool {
    if entropy < MIXED_TOKEN_ENTROPY_FLOOR
        || candidate.len() < KEYWORD_FREE_MIN_LEN
        || !candidate.contains('_')
    {
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

const LOWER_DASH_APP_PASSWORD_LEN: usize = 19;
pub(super) const ISOLATED_SPECIAL_SHAPE_MIN_LEN: usize = 16;

fn isolated_special_shape_floor_met(candidate: &str, entropy: f64) -> bool {
    lower_dash_app_password_floor_met(candidate, entropy)
        || (candidate.len() >= ISOLATED_SPECIAL_SHAPE_MIN_LEN
            && symbolic_isolated_bare_candidate(candidate))
}

pub(crate) fn lower_dash_app_password_floor_met(candidate: &str, entropy: f64) -> bool {
    const LOWER_DASH_APP_PASSWORD_THRESHOLD: f64 = 3.9;
    // Four `-`-separated groups of 4 chars + 3 dashes = 19 (e.g. `a1b2-c3d4-e5f6-g7h8`).
    if entropy < LOWER_DASH_APP_PASSWORD_THRESHOLD || candidate.len() != LOWER_DASH_APP_PASSWORD_LEN
    {
        return false;
    }

    let mut has_non_hex = false;
    let mut group_count = 0usize;
    for group in candidate.split('-') {
        group_count += 1;
        if group.len() != 4 {
            return false;
        }
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

    group_count == 4 && has_non_hex
}

pub(crate) fn mixed_contiguous_token_floor_met(candidate: &str, entropy: f64) -> bool {
    if entropy < MIXED_TOKEN_ENTROPY_FLOOR || candidate.len() < KEYWORD_FREE_MIN_LEN {
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

#[allow(dead_code)] // Retained as wrapper; production uses _inner variant
pub(super) fn collect_isolated_bare_candidates(
    line: &str,
    line_idx: usize,
    line_offset: usize,
    context: &KeywordContext,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
    placeholder_keywords: &[String],
) {
    if is_likely_innocuous_line(line) {
        return;
    }
    collect_isolated_bare_candidates_inner(
        line,
        line_idx,
        line_offset,
        context,
        seen,
        matches,
        placeholder_keywords,
    );
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
    visit_isolated_bare_candidates(line, context.min_len, &mut emit_candidate);
    // See the matching admission exception in
    // `line_has_isolated_bare_secret_candidate`: only shape-proven symbolic or
    // 4x4 app-password candidates may cross a broader detector TOML floor.
    if context.min_len > ISOLATED_SPECIAL_SHAPE_MIN_LEN {
        visit_isolated_bare_candidates(
            line,
            ISOLATED_SPECIAL_SHAPE_MIN_LEN,
            |candidate, candidate_offset| {
                let entropy = shannon_entropy(candidate.as_bytes());
                if candidate.len() < context.min_len
                    && isolated_special_shape_floor_met(candidate, entropy)
                {
                    emit_candidate(candidate, candidate_offset);
                }
            },
        );
    }
}

fn isolated_bare_secret_entropy(
    candidate: &str,
    threshold: f64,
    placeholder_keywords: &[String],
) -> Option<f64> {
    match isolated_bare_secret_entropy_decision(candidate, threshold, placeholder_keywords) {
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
) -> Result<f64, StageId> {
    if super::scanner::is_canonical_non_secret_shape(candidate) {
        return Err(StageId::EntropyValueShape(
            EntropyShapeStage::CanonicalNonSecretShape,
        ));
    }
    let entropy = shannon_entropy(candidate.as_bytes());
    if !isolated_bare_entropy_floor_met(candidate, entropy, threshold) {
        return Err(StageId::EntropyBelowFloor);
    }
    if !is_isolated_bare_secret_plausible(candidate, placeholder_keywords) {
        return Err(StageId::EntropyValueShape(
            EntropyShapeStage::SecretPlausibilityRejected,
        ));
    }
    Ok(entropy)
}

fn visit_isolated_bare_candidates<'a>(
    line: &'a str,
    min_len: usize,
    mut visit: impl FnMut(&'a str, usize),
) {
    // Fast path: check for whitespace BEFORE the expensive full-line
    // `isolated_bare_candidate` call. `isolated_bare_candidate` does
    // `line.trim().trim_matches(...)` + length + whitespace check, which is
    // ~3 byte passes over the full line. For multi-word lines (the common
    // case in source code — ~99% of lines), the full-line check always
    // returns None because the candidate has whitespace. Checking for
    // whitespace first lets us skip straight to per-token scanning, saving
    // ~2 byte passes per line (~24ms across 9 windows at 8 MiB).
    let bytes = line.as_bytes();
    let has_whitespace = bytes.iter().any(|&b| b.is_ascii_whitespace());
    if !has_whitespace {
        if let Some(candidate) = isolated_bare_candidate(line, min_len) {
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
            isolated_bare_candidate_in_span(line, token_start, token_end, min_len)
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
    // computation would run — only to reject it for low entropy.
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
    isolated_bare_candidate(candidate, min_len).map(|value| {
        // SAFETY: `value` is a subslice of `candidate` (via str::trim/trim_matches inside
        // `isolated_bare_candidate`), and `candidate` is `&line[candidate_start..candidate_end]`
        // — a direct subslice of `line`. Therefore `value.as_ptr() >= line.as_ptr()` is
        // guaranteed; subtraction cannot underflow.
        let offset = value.as_ptr() as usize - line.as_ptr() as usize;
        (value, offset)
    })
}

fn isolated_bare_candidate(line: &str, min_len: usize) -> Option<&str> {
    let candidate = line.trim().trim_matches(|c: char| c == ';' || c == ',');
    if candidate.len() < min_len || candidate.bytes().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    let has_alpha = candidate.bytes().any(|b| b.is_ascii_alphabetic());
    let has_digit = candidate.bytes().any(|b| b.is_ascii_digit());
    let no_digit_symbolic_token = !has_digit && symbolic_alpha_only_opaque_candidate(candidate);
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
        || colon_separated_opaque_candidate(candidate)
        || no_digit_symbolic_token
        || (!has_assignment_equals && symbolic_isolated_bare_candidate(candidate))
        || bang_led_symbolic_token
    {
        return Some(candidate);
    }
    None
}

pub(crate) fn colon_separated_opaque_candidate(candidate: &str) -> bool {
    if candidate.contains("://") || candidate.bytes().filter(|&b| b == b':').count() != 1 {
        return false;
    }
    let Some((left, right)) = candidate.split_once(':') else {
        return false;
    };
    if left.len() < KEYWORD_FREE_MIN_LEN || right.len() < COLON_RIGHT_PART_MIN_LEN {
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

pub(crate) fn symbolic_alpha_only_opaque_candidate(candidate: &str) -> bool {
    if candidate.len() < SYMBOLIC_ALPHA_ONLY_MIN_LEN || candidate.contains("://") {
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
    use super::isolated_bare_entropy_threshold;
    use crate::entropy::{HIGH_ENTROPY_THRESHOLD, MIXED_ALNUM_TOKEN_THRESHOLD};

    /// The isolated-bare floor defaults to [`MIXED_ALNUM_TOKEN_THRESHOLD`] (4.0)
    /// for the default 4.5 threshold, every value at or below the high floor, and
    /// non-finite inputs; only a threshold STRICTLY above the high floor is
    /// honored verbatim (the shared override owner). Proves the dedup preserved
    /// the isolated site's exact resolution at every band.
    #[test]
    fn isolated_floor_defaults_to_mixed_and_overrides_only_above_high() {
        assert_eq!(
            isolated_bare_entropy_threshold(HIGH_ENTROPY_THRESHOLD),
            MIXED_ALNUM_TOKEN_THRESHOLD
        );
        assert_eq!(
            isolated_bare_entropy_threshold(4.0),
            MIXED_ALNUM_TOKEN_THRESHOLD
        );
        assert_eq!(
            isolated_bare_entropy_threshold(2.0),
            MIXED_ALNUM_TOKEN_THRESHOLD
        );
        assert_eq!(
            isolated_bare_entropy_threshold(f64::NAN),
            MIXED_ALNUM_TOKEN_THRESHOLD
        );
        assert_eq!(isolated_bare_entropy_threshold(5.8), 5.8);
        assert_eq!(isolated_bare_entropy_threshold(8.0), 8.0);
    }
}
