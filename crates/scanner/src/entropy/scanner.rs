use super::{
    keywords::*, shannon_entropy, EntropyMatch, LOW_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD,
};

const CREDENTIAL_CONTEXT_MIN_LEN: usize = 8;
const KEYWORD_FREE_MIN_LEN: usize = 20;
const MIN_PASSWORD_LEN: usize = 8;
const FIRST_SOURCE_LINE_NUMBER: usize = 1;
const KEYWORD_FREE_LABEL: &str = "none (high-entropy)";

/// Test-only constructor for a credential-anchor [`KeywordContext`] using the
/// production tuning constants (the low-entropy floor and the credential-context
/// minimum length). Exposed (doc-hidden, via `testing::entropy_scanner`) so the
/// canonical-shape tests in `tests/unit/inline_migrated/` can build the same
/// context the scanner uses, without leaking the private length constant.
#[doc(hidden)]
pub fn credential_keyword_context(keyword: &str) -> KeywordContext {
    KeywordContext {
        keyword: keyword.to_string(),
        threshold: LOW_ENTROPY_THRESHOLD,
        min_len: CREDENTIAL_CONTEXT_MIN_LEN,
        is_credential_context: true,
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
    let lines: Vec<&str> = text.lines().collect();
    let line_offsets = cumulative_line_offsets(&lines);
    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let keyword_lines = find_keyword_assignment_lines(&lines, secret_keywords);

    scan_keyword_contexts(
        &lines,
        &line_offsets,
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
    );
    scan_keyword_free_candidates(
        &lines,
        &line_offsets,
        entropy_threshold,
        keyword_free_threshold,
        &mut seen,
        &mut matches,
        placeholder_keywords,
        skip_lines,
    );
    matches
}

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
) {
    for (keyword_line_index, keyword_line) in keyword_lines {
        let context = keyword_context(keyword_line, min_length, entropy_threshold, secret_keywords);
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
    };
    for (line_idx, line) in lines.iter().enumerate() {
        if let Some(skip) = skip_lines {
            if skip.contains(&line_idx) {
                continue;
            }
        }
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

pub fn candidate_is_plausible(
    candidate: &str,
    entropy: f64,
    context: &KeywordContext,
    placeholder_keywords: &[String],
) -> bool {
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
        if is_canonical_non_secret_shape(candidate) {
            return false;
        }
        return candidate.len() >= MIN_PASSWORD_LEN;
    }
    candidate.len() >= KEYWORD_FREE_MIN_LEN.min(context.min_len)
        && is_secret_plausible(candidate, placeholder_keywords)
}

/// True when `value` is EXACTLY a canonical non-secret shape: a hash digest,
/// UUID, npm integrity string, or license serial. These keep their shape
/// regardless of any surrounding credential keyword, so a generic entropy
/// anchor must not re-admit them. Service-specific detector regexes (not this
/// path) own the rare case where such a shape really is a credential.
pub fn is_canonical_non_secret_shape(value: &str) -> bool {
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
            if !body.is_empty()
                && body
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
            {
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

fn cumulative_line_offsets(lines: &[&str]) -> Vec<usize> {
    let mut offsets = Vec::with_capacity(lines.len());
    let mut current = 0usize;
    for line in lines {
        offsets.push(current);
        current = current.saturating_add(line.len().saturating_add(1));
    }
    offsets
}

fn keyword_context(
    keyword_line: &str,
    min_length: usize,
    entropy_threshold: f64,
    secret_keywords: &[String],
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
    let keyword = secret_keywords
        .iter()
        .find(|keyword| contains_ci(line_bytes, keyword.as_bytes()))
        .map(|keyword| keyword.as_str())
        .unwrap_or("unknown");
    let is_credential_context = CREDENTIAL_KEYWORDS
        .iter()
        .any(|credential_keyword| contains_ci(line_bytes, credential_keyword.as_bytes()));

    let base_threshold = entropy_threshold.min(LOW_ENTROPY_THRESHOLD);

    KeywordContext {
        keyword: keyword.to_string(),
        threshold: base_threshold,
        min_len: if is_credential_context {
            CREDENTIAL_CONTEXT_MIN_LEN
        } else {
            min_length
        },
        is_credential_context,
    }
}

