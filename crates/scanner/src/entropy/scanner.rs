use super::{
    keywords::*, shannon_entropy, EntropyMatch, HIGH_ENTROPY_THRESHOLD,
    ISOLATED_BARE_ENTROPY_LABEL, LOW_ENTROPY_THRESHOLD, MIXED_ALNUM_TOKEN_THRESHOLD,
    VERY_HIGH_ENTROPY_THRESHOLD,
};

const CREDENTIAL_CONTEXT_MIN_LEN: usize = 8;
const KEYWORD_FREE_MIN_LEN: usize = 20;
const KEYWORD_FREE_ISOLATED_MIN_LEN: usize = 16;
const MIN_PASSWORD_LEN: usize = 8;
const FIRST_SOURCE_LINE_NUMBER: usize = 1;
const KEYWORD_FREE_LABEL: &str = "none (high-entropy)";

/// Test-only constructor for a credential-anchor [`KeywordContext`] using the
/// production tuning constants (the low-entropy floor and the credential-context
/// minimum length). Exposed (doc-hidden, via `testing::entropy_scanner`) so the
/// canonical-shape tests in `tests/unit/inline_migrated/` can build the same
/// context the scanner uses, without leaking the private length constant.
#[doc(hidden)]
#[cfg(test)]
pub(crate) fn credential_keyword_context(keyword: &str) -> KeywordContext {
    credential_keyword_context_with_lift(keyword, false)
}

/// Lift-aware sibling of [`credential_keyword_context`]: builds the same
/// production credential anchor but with `allow_canonical_shapes` set to
/// `allow_canonical_lift`. Exposed (doc-hidden, via `testing::entropy_scanner`)
/// so the CredData recall-lane unit tests can drive `candidate_is_plausible`
/// through both the strict gate and the model-arbitrated lift.
#[doc(hidden)]
#[cfg(test)]
pub(crate) fn credential_keyword_context_with_lift(
    keyword: &str,
    allow_canonical_lift: bool,
) -> KeywordContext {
    KeywordContext {
        keyword: keyword.to_string(),
        threshold: LOW_ENTROPY_THRESHOLD,
        min_len: CREDENTIAL_CONTEXT_MIN_LEN,
        is_credential_context: true,
        allow_canonical_shapes: allow_canonical_lift,
    }
}

/// Determine whether a file path represents a clearly sensitive file.
pub fn is_sensitive_file(path: Option<&str>) -> bool {
    let Some(path) = path else { return false };
    // Case-insensitive suffix check without allocating a lowercased
    // copy of the entire path on every call. Compares the trailing
    // bytes of `path` against the literal extension byte-for-byte.
    const EXTS: &[&[u8]] = &[
        b".env",
        b".pem",
        b".key",
        b".secrets",
        b".tfvars",
        b".p12",
        b".pkcs12",
        b".jks",
    ];
    let bytes = path.as_bytes();
    EXTS.iter().any(|ext| {
        bytes.len() >= ext.len() && bytes[bytes.len() - ext.len()..].eq_ignore_ascii_case(ext)
    })
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
    find_entropy_secrets_with_threshold(
        text,
        min_length,
        context_lines,
        entropy_threshold,
        VERY_HIGH_ENTROPY_THRESHOLD,
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
    debug_assert!(
        line_offsets.len() >= lines.len(),
        "entropy line offsets must cover every split line"
    );
    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let keyword_lines = find_keyword_assignment_lines(lines, secret_keywords);

    scan_keyword_contexts(
        lines,
        line_offsets,
        &keyword_lines,
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
) {
    for (keyword_line_index, keyword_line) in keyword_lines {
        let context = keyword_context(
            keyword_line,
            min_length,
            entropy_threshold,
            secret_keywords,
            allow_canonical_lift,
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
            );
        }
    }
}

fn scan_keyword_free_candidates(
    lines: &[&str],
    line_offsets: &[usize],
    entropy_threshold: f64,
    keyword_free_threshold: f64,
    seen: &mut std::collections::HashSet<String>,
    matches: &mut Vec<EntropyMatch>,
    placeholder_keywords: &[String],
    skip_lines: Option<&std::collections::HashSet<usize>>,
) {
    let effective_keyword_free_threshold = keyword_free_threshold.max(entropy_threshold + 1.0);
    let keyword_free_context = KeywordContext {
        keyword: KEYWORD_FREE_LABEL.to_string(),
        threshold: effective_keyword_free_threshold,
        min_len: KEYWORD_FREE_MIN_LEN,
        is_credential_context: false,
        // Keyword-FREE: no credential anchor ⇒ no positive evidence ⇒ the
        // canonical hash/UUID-shape gate stays strict here unconditionally,
        // regardless of model authority. The lift is anchor-gated.
        allow_canonical_shapes: false,
    };
    let isolated_token_context = KeywordContext {
        keyword: ISOLATED_BARE_ENTROPY_LABEL.to_string(),
        threshold: isolated_bare_entropy_threshold(entropy_threshold),
        min_len: KEYWORD_FREE_ISOLATED_MIN_LEN,
        is_credential_context: false,
        allow_canonical_shapes: false,
    };
    for (line_idx, line) in lines.iter().enumerate() {
        if let Some(skip) = skip_lines {
            if skip.contains(&line_idx) {
                continue;
            }
        }
        collect_isolated_bare_candidate(
            line,
            line_idx,
            line_offsets[line_idx],
            &isolated_token_context,
            seen,
            matches,
            placeholder_keywords,
        );
        collect_line_candidates(
            line,
            line_idx,
            line_offsets[line_idx],
            &keyword_free_context,
            seen,
            matches,
            placeholder_keywords,
        );
    }
}

#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) fn has_isolated_bare_secret_candidate(
    text: &str,
    entropy_threshold: f64,
    placeholder_keywords: &[String],
) -> bool {
    let lines: Vec<&str> = text.lines().collect();
    has_isolated_bare_secret_candidate_with_lines(&lines, entropy_threshold, placeholder_keywords)
}

#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) fn has_isolated_bare_secret_candidate_with_lines(
    lines: &[&str],
    entropy_threshold: f64,
    placeholder_keywords: &[String],
) -> bool {
    let threshold = isolated_bare_entropy_threshold(entropy_threshold);
    lines.iter().any(|line| {
        if is_likely_innocuous_line(line) {
            return false;
        }
        let Some(candidate) = isolated_bare_candidate(line, KEYWORD_FREE_ISOLATED_MIN_LEN) else {
            return false;
        };
        if is_canonical_non_secret_shape(candidate) {
            return false;
        }
        let entropy = shannon_entropy(candidate.as_bytes());
        isolated_bare_entropy_floor_met(candidate, entropy, threshold)
            && is_isolated_bare_secret_plausible(candidate, placeholder_keywords)
    })
}

#[cfg(any(feature = "simd", feature = "gpu", feature = "entropy"))]
pub(crate) fn has_lower_dash_app_password_candidate_with_lines(
    lines: &[&str],
    config: &crate::ScannerConfig,
) -> bool {
    for (_, keyword_line) in find_keyword_assignment_lines(lines, &config.secret_keywords) {
        if is_likely_innocuous_line(keyword_line) {
            continue;
        }
        let context = keyword_context(
            keyword_line,
            config.min_secret_len,
            config.entropy_threshold,
            &config.secret_keywords,
            false,
        );
        for candidate in extract_candidates(
            keyword_line,
            context.min_len,
            &config.placeholder_keywords,
            context.is_credential_context,
            false,
        ) {
            let entropy = shannon_entropy(candidate.as_bytes());
            if lower_dash_app_password_floor_met(&candidate, entropy)
                && candidate_is_plausible(
                    &candidate,
                    entropy,
                    &context,
                    &config.placeholder_keywords,
                )
            {
                return true;
            }
        }
    }
    false
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

fn mixed_contiguous_token_floor_met(candidate: &str, entropy: f64) -> bool {
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

fn collect_isolated_bare_candidate(
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
    let Some(candidate) = isolated_bare_candidate(line, context.min_len) else {
        return;
    };
    if is_canonical_non_secret_shape(candidate) {
        return;
    }
    let entropy = shannon_entropy(candidate.as_bytes());
    if !isolated_bare_entropy_floor_met(candidate, entropy, context.threshold)
        || !is_isolated_bare_secret_plausible(candidate, placeholder_keywords)
        || !seen.insert(candidate.to_string())
    {
        return;
    }
    matches.push(EntropyMatch {
        value: candidate.to_string(),
        entropy,
        keyword: context.keyword.clone(),
        line: line_idx + FIRST_SOURCE_LINE_NUMBER,
        offset: line_offset,
    });
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

fn collect_line_candidates(
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

    for candidate in extract_candidates(
        line,
        context.min_len,
        placeholder_keywords,
        context.is_credential_context,
        context.allow_canonical_shapes,
    ) {
        let entropy = shannon_entropy(candidate.as_bytes());
        if !candidate_is_plausible(&candidate, entropy, context, placeholder_keywords)
            || !seen.insert(candidate.clone())
        {
            continue;
        }
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
    if crate::engine::phase2_generic::shape_helpers::is_structured_dotted_token(candidate) {
        return candidate.len() >= KEYWORD_FREE_MIN_LEN.min(context.min_len);
    }
    if entropy < context.threshold {
        return false;
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
            return false;
        }
        return candidate.len() >= MIN_PASSWORD_LEN;
    }
    candidate.len() >= KEYWORD_FREE_MIN_LEN.min(context.min_len)
        && is_secret_plausible(
            candidate,
            placeholder_keywords,
            crate::entropy::keywords::PlausibilityContext::default(),
        )
}

/// True when `value` is EXACTLY a canonical non-secret shape: a hash digest,
/// UUID, npm integrity string, or license serial. These keep their shape
/// regardless of any surrounding credential keyword, so a generic entropy
/// anchor must not re-admit them. Service-specific detector regexes (not this
/// path) own the rare case where such a shape really is a credential.
pub(crate) fn is_canonical_non_secret_shape(value: &str) -> bool {
    let len = value.len();

    // 8-4-4-4-12 UUID / k8s-resource-uid (36 chars, hex groups split by `-`).
    if len == 36 {
        let bytes = value.as_bytes();
        if bytes[8] == b'-'
            && bytes[13] == b'-'
            && bytes[18] == b'-'
            && bytes[23] == b'-'
            && value.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit())
        {
            return true;
        }
    }

    // Pure-hex digests at canonical lengths: md5(32), sha1/git-commit-sha(40),
    // sha256(64), sha512(128). npm-lock-integrity hex bodies land here too.
    if matches!(len, 32 | 40 | 64 | 128) && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }

    // npm Subresource Integrity: `sha512-<base64>` / `sha384-` / `sha256-`.
    for prefix in ["sha512-", "sha384-", "sha256-"] {
        if let Some(body) = value.strip_prefix(prefix) {
            if !body.is_empty() && crate::decode::standard_base64_shape(body).is_some() {
                return true;
            }
        }
    }

    // License serial: 5 dash-joined groups of 5 uppercase-alphanumeric chars
    // (`JQQJN-VBWHG-...`, `ABCDE-FGHIJ-KLMNO-PQRST-UVWXY`).
    if len == 29 && value.as_bytes().iter().filter(|&&b| b == b'-').count() == 4 {
        let groups: Vec<&str> = value.split('-').collect();
        if groups.len() == 5
            && groups.iter().all(|g| {
                g.len() == 5
                    && g.bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            })
        {
            return true;
        }
    }

    false
}

/// True iff the model-authoritative canonical-shape lift may release this exact
/// value shape under this exact keyword. The lift is intentionally narrower than
/// "credential context": mirror negatives wrap sha1/git SHAs in `api_key=` and
/// `secret=`, so hex40 must never lift, and sha256-length hex64 only lifts under
/// explicit cryptographic-key anchors where an AES-256/key-material value is a
/// plausible credential.
pub(crate) fn canonical_shape_lift_allowed(value: &str, keyword: &str) -> bool {
    if is_uuid_shape(value) {
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

fn is_uuid_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    value.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && value.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit())
}

fn keyword_is_crypto_key_material(keyword: &str) -> bool {
    let compact = compact_keyword(keyword);
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
    .any(|needle| compact.contains(needle))
}

fn keyword_is_key_material(keyword: &str) -> bool {
    let compact = compact_keyword(keyword);
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
    .any(|needle| compact.contains(needle))
}

fn compact_keyword(keyword: &str) -> String {
    keyword
        .bytes()
        .filter(|b| !matches!(b, b'_' | b'-' | b'.'))
        .map(|b| b.to_ascii_lowercase() as char)
        .collect()
}

fn keyword_context(
    keyword_line: &str,
    min_length: usize,
    entropy_threshold: f64,
    secret_keywords: &[String],
    allow_canonical_lift: bool,
) -> KeywordContext {
    const CREDENTIAL_KEYWORDS: &[&str] = &[
        "password",
        "passwd",
        "pwd",
        "db_pass",
        "db_password",
        "api_key",
        "apikey",
        "api-key",
        "auth",
        "authorization",
        "bearer",
        "_key",
        "-key",
        "token",
        "_token",
        "-token",
        "secret",
        "_secret",
        "-secret",
    ];

    // ASCII case-insensitive substring search - avoids the
    // per-call `keyword_line.to_lowercase()` and per-keyword
    // `keyword.to_lowercase()` allocations the previous flow did
    // on every entropy candidate. Mirrors `is_keyword_assignment_line`
    // which already uses `eq_ignore_ascii_case` over byte windows.
    let line_bytes = keyword_line.as_bytes();
    fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > haystack.len() {
            return false;
        }
        haystack
            .windows(needle.len())
            .any(|w| w.eq_ignore_ascii_case(needle))
    }
    let exact_assignment_keyword =
        crate::entropy::keywords::assignment_keyword_for_line(keyword_line);
    let keyword = exact_assignment_keyword
        .as_deref()
        .or_else(|| {
            secret_keywords
                .iter()
                .find(|keyword| contains_ci(line_bytes, keyword.as_bytes()))
                .map(|keyword| keyword.as_str())
        })
        .unwrap_or("unknown"); // LAW10: absent path/field => display placeholder; reporting-only, recall-safe
    let is_exact_credential_context = exact_assignment_keyword
        .as_deref()
        .is_some_and(crate::entropy::keywords::normalized_assignment_keyword_is_credential);
    let is_credential_context = is_exact_credential_context
        || CREDENTIAL_KEYWORDS
            .iter()
            .any(|credential_keyword| contains_ci(line_bytes, credential_keyword.as_bytes()));

    let base_threshold =
        if entropy_threshold.is_finite() && entropy_threshold > HIGH_ENTROPY_THRESHOLD {
            entropy_threshold
        } else if entropy_threshold.is_finite() {
            entropy_threshold.min(LOW_ENTROPY_THRESHOLD)
        } else {
            LOW_ENTROPY_THRESHOLD
        };

    KeywordContext {
        keyword: keyword.to_string(),
        threshold: base_threshold,
        min_len: if is_credential_context {
            CREDENTIAL_CONTEXT_MIN_LEN
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
