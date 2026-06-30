use super::keywords::{is_likely_innocuous_line, KeywordContext};
use super::plausibility::is_isolated_bare_secret_plausible;
use super::{
    shannon_entropy, EntropyMatch, HIGH_ENTROPY_THRESHOLD, ISOLATED_BARE_ENTROPY_LABEL,
    MIXED_ALNUM_TOKEN_THRESHOLD,
};
use crate::adjudicate::{EntropyShapeStage, StageId};

const KEYWORD_FREE_ISOLATED_MIN_LEN: usize = 16;
const FIRST_SOURCE_LINE_NUMBER: usize = 1;

#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) fn has_isolated_bare_secret_candidate(
    text: &str,
    entropy_threshold: f64,
    placeholder_keywords: &[String],
) -> bool {
    // Stream `text.lines()` straight into `.any()` instead of collecting a
    // `Vec<&str>` first (Law 7: this runs twice per coalesced chunk in
    // scan_coalesced.rs — the temporary line vector was a pure per-call
    // allocation). `text.lines()` yields exactly the same `&str` sequence the
    // collected slice did, so this is byte-for-byte equivalent.
    let threshold = isolated_bare_entropy_threshold(entropy_threshold);
    text.lines()
        .any(|line| line_has_isolated_bare_secret_candidate(line, threshold, placeholder_keywords))
}

#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) fn has_isolated_bare_secret_candidate_with_lines(
    lines: &[&str],
    entropy_threshold: f64,
    placeholder_keywords: &[String],
) -> bool {
    let threshold = isolated_bare_entropy_threshold(entropy_threshold);
    lines
        .iter()
        .any(|line| line_has_isolated_bare_secret_candidate(line, threshold, placeholder_keywords))
}

/// Per-line predicate shared by the `&str` and `&[&str]` entry points so the
/// innocuous-line skip + candidate-visit logic has one definition. `threshold`
/// is already resolved by [`isolated_bare_entropy_threshold`] at the caller.
#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
fn line_has_isolated_bare_secret_candidate(
    line: &str,
    threshold: f64,
    placeholder_keywords: &[String],
) -> bool {
    if is_likely_innocuous_line(line) {
        return false;
    }
    let mut found = false;
    visit_isolated_bare_candidates(line, KEYWORD_FREE_ISOLATED_MIN_LEN, |candidate, _| {
        found |= isolated_bare_secret_entropy(candidate, threshold, placeholder_keywords).is_some();
    });
    found
}

fn isolated_bare_entropy_threshold(entropy_threshold: f64) -> f64 {
    if entropy_threshold.is_finite() && entropy_threshold > HIGH_ENTROPY_THRESHOLD {
        entropy_threshold
    } else {
        MIXED_ALNUM_TOKEN_THRESHOLD
    }
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

pub(super) fn isolated_bare_keyword_context(entropy_threshold: f64) -> KeywordContext {
    KeywordContext {
        keyword: ISOLATED_BARE_ENTROPY_LABEL.to_string(),
        threshold: isolated_bare_entropy_threshold(entropy_threshold),
        min_len: KEYWORD_FREE_ISOLATED_MIN_LEN,
        is_credential_context: false,
        allow_canonical_shapes: false,
    }
}

pub(crate) fn mixed_separator_token_floor_met(candidate: &str, entropy: f64) -> bool {
    const MIXED_SEPARATOR_TOKEN_THRESHOLD: f64 = 3.65;
    if entropy < MIXED_SEPARATOR_TOKEN_THRESHOLD || candidate.len() < 20 || !candidate.contains('_')
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

pub(crate) fn lower_dash_app_password_floor_met(candidate: &str, entropy: f64) -> bool {
    const LOWER_DASH_APP_PASSWORD_THRESHOLD: f64 = 3.9;
    if entropy < LOWER_DASH_APP_PASSWORD_THRESHOLD || candidate.len() != 19 {
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
    const MIXED_CONTIGUOUS_TOKEN_THRESHOLD: f64 = 3.65;
    if entropy < MIXED_CONTIGUOUS_TOKEN_THRESHOLD || candidate.len() < 20 {
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
    visit_isolated_bare_candidates(line, context.min_len, |candidate, candidate_offset| {
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
    });
}

fn isolated_bare_secret_entropy(
    candidate: &str,
    threshold: f64,
    placeholder_keywords: &[String],
) -> Option<f64> {
    match isolated_bare_secret_entropy_decision(candidate, threshold, placeholder_keywords) {
        Ok(entropy) => Some(entropy),
        Err(_error) => {
            // LAW10: test/probe adapter only; production calls the Result-returning decision helper and records typed adjudication stages.
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
    if let Some(candidate) = isolated_bare_candidate(line, min_len) {
        let candidate_offset = candidate.as_ptr() as usize - line.as_ptr() as usize;
        visit(candidate, candidate_offset);
        return;
    }

    if !line.bytes().any(|b| b.is_ascii_whitespace()) {
        return;
    }

    let bytes = line.as_bytes();
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
    isolated_bare_candidate(candidate, min_len).map(|value| {
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
    let has_assignment_equals = has_non_padding_equals(candidate);
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

fn colon_separated_opaque_candidate(candidate: &str) -> bool {
    if candidate.contains("://") || candidate.bytes().filter(|&b| b == b':').count() != 1 {
        return false;
    }
    let Some((left, right)) = candidate.split_once(':') else {
        return false;
    };
    if left.len() < 20 || right.len() < 16 {
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

fn symbolic_alpha_only_opaque_candidate(candidate: &str) -> bool {
    if candidate.len() < 18 || candidate.contains("://") {
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

fn symbolic_isolated_bare_candidate(candidate: &str) -> bool {
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

fn has_non_padding_equals(candidate: &str) -> bool {
    let padding = candidate.bytes().rev().take_while(|&b| b == b'=').count();
    if padding > 2 {
        return true;
    }
    candidate[..candidate.len() - padding].contains('=')
}
