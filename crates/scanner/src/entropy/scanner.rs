use super::{
    keywords::*, shannon_entropy, EntropyMatch, LOW_ENTROPY_THRESHOLD, VERY_HIGH_ENTROPY_THRESHOLD,
};

const CREDENTIAL_CONTEXT_MIN_LEN: usize = 8;
const KEYWORD_FREE_MIN_LEN: usize = 20;
const MIN_PASSWORD_LEN: usize = 8;
const FIRST_SOURCE_LINE_NUMBER: usize = 1;
const KEYWORD_FREE_LABEL: &str = "none (high-entropy)";

/// Determine whether a file path represents a clearly sensitive file.
pub fn is_sensitive_file(path: Option<&str>) -> bool {
    let Some(path) = path else { return false };
    let lower = path.to_lowercase();
    [
        ".env", ".pem", ".key", ".secrets", ".tfvars", ".p12", ".pkcs12", ".jks",
    ]
    .iter()
    .any(|ext| lower.ends_with(ext))
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

    for candidate in extract_candidates(line, context.min_len, placeholder_keywords) {
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

fn candidate_is_plausible(
    candidate: &str,
    entropy: f64,
    context: &KeywordContext,
    placeholder_keywords: &[String],
) -> bool {
    if entropy < context.threshold {
        return false;
    }
    if context.is_credential_context {
        return candidate.len() >= MIN_PASSWORD_LEN;
    }
    candidate.len() >= KEYWORD_FREE_MIN_LEN.min(context.min_len)
        && is_secret_plausible(candidate, placeholder_keywords)
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

    let lowered = keyword_line.to_lowercase();
    let keyword = secret_keywords
        .iter()
        .find(|keyword| lowered.contains(&keyword.to_lowercase()))
        .map(|keyword| keyword.as_str())
        .unwrap_or("unknown");
    let is_credential_context = CREDENTIAL_KEYWORDS
        .iter()
        .any(|credential_keyword| lowered.contains(credential_keyword));

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
