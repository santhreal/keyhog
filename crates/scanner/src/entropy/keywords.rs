use super::{shannon_entropy, HIGH_ENTROPY_THRESHOLD};

pub(super) struct KeywordContext {
    pub keyword: String,
    pub threshold: f64,
    pub min_len: usize,
    pub is_credential_context: bool,
}

pub(super) fn find_keyword_assignment_lines<'a>(
    lines: &'a [&str],
    secret_keywords: &[String],
) -> Vec<(usize, &'a str)> {
    lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            is_keyword_assignment_line(line, secret_keywords).then_some((index, *line))
        })
        .collect()
}

fn is_keyword_assignment_line(line: &str, secret_keywords: &[String]) -> bool {
    let line_bytes = line.as_bytes();
    let has_keyword = secret_keywords.iter().any(|keyword| {
        let keyword_bytes = keyword.as_bytes();
        line_bytes
            .windows(keyword_bytes.len())
            .any(|window| window.eq_ignore_ascii_case(keyword_bytes))
    });
    let trimmed = line.trim();
    let is_import = trimmed.starts_with("import")
        || trimmed.starts_with("package")
        || trimmed.starts_with("use ")
        || trimmed.starts_with("from ")
        || trimmed.starts_with("require(");
    has_keyword && (line.contains('=') || line.contains(':')) && !is_import
}

pub(super) fn is_likely_innocuous_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with("import ")
        || trimmed.starts_with("from ")
        || trimmed.starts_with("require(")
        || trimmed.starts_with("use ")
        || trimmed.starts_with("package ")
        || trimmed.starts_with("include ")
        || trimmed.starts_with("#include ")
        || trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("ftp://")
        || trimmed.starts_with("file://")
        || trimmed.starts_with("ssh://")
        || trimmed.starts_with("git://")
    {
        return true;
    }

    let without_quotes = trimmed.trim_matches(|c: char| c == '"' || c == '\'' || c == ',');
    if without_quotes.starts_with("sha256:")
        || without_quotes.starts_with("sha512:")
        || without_quotes.starts_with("sha1:")
        || without_quotes.starts_with("md5:")
        || without_quotes.starts_with("git-sha:")
    {
        return true;
    }
    without_quotes.len() == 40 && without_quotes.chars().all(|c| c.is_ascii_hexdigit())
}

pub(super) fn extract_candidates(
    line: &str,
    min_length: usize,
    placeholder_keywords: &[String],
    is_credential_context: bool,
) -> Vec<String> {
    let mut candidates = Vec::new();
    if is_likely_concatenation_fragment(line) {
        return candidates;
    }

    if let Some(sep_pos) = line.find('=').or_else(|| line.find(':')) {
        let cleaned = line[sep_pos + 1..]
            .trim()
            .trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ';' || c == ',');
        if cleaned.len() >= min_length
            && is_candidate_plausible_with_context(
                cleaned,
                placeholder_keywords,
                is_credential_context,
            )
        {
            candidates.push(cleaned.to_string());
        }
    }

    for quote in ['"', '\''] {
        let mut start = None;
        for (index, ch) in line.char_indices() {
            if ch == quote {
                match start {
                    None => start = Some(index + 1),
                    Some(begin) => {
                        let content = &line[begin..index];
                        if content.len() >= min_length
                            && is_secret_plausible_with_context(
                                content,
                                placeholder_keywords,
                                is_credential_context,
                            )
                        {
                            candidates.push(content.to_string());
                        }
                        start = None;
                    }
                }
            }
        }
    }

    candidates
}

fn is_likely_concatenation_fragment(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with('"') || trimmed.starts_with('\'') {
        let double_quotes = trimmed.matches('"').count();
        let single_quotes = trimmed.matches('\'').count();
        if (double_quotes == 2 && single_quotes == 0) || (single_quotes == 2 && double_quotes == 0)
        {
            let after_quote = if double_quotes == 2 {
                trimmed
                    .rfind('"')
                    .map(|index| &trimmed[index + 1..])
                    .unwrap_or("")
                    .trim()
            } else {
                trimmed
                    .rfind('\'')
                    .map(|index| &trimmed[index + 1..])
                    .unwrap_or("")
                    .trim()
            };
            let is_fragment_suffix = after_quote.is_empty()
                || after_quote == "+"
                || after_quote == "\\"
                || after_quote == ","
                || after_quote == ")"
                || after_quote.starts_with('+')
                || after_quote.starts_with(')');
            if is_fragment_suffix {
                return true;
            }
        }
    }
    trimmed.ends_with("\\\"") || trimmed.ends_with("-\\")
}

enum PlausibilityMode {
    Lenient,
    Strict,
}

fn is_known_non_secret(value: &str, is_credential_context: bool) -> bool {
    if value.len() == 36 {
        let bytes = value.as_bytes();
        if bytes[8] == b'-'
            && bytes[13] == b'-'
            && bytes[18] == b'-'
            && bytes[23] == b'-'
            && value
                .chars()
                .filter(|&ch| ch != '-')
                .all(|ch| ch.is_ascii_hexdigit())
        {
            return true;
        }
    }

    // Pure-hex 32/40/64/128 char strings are usually file/commit/image digests
    // (MD5/SHA1/SHA256/SHA512). Outside a credential-keyword anchor, drop them
    // so the entropy fallback doesn't emit on `sha256: <hex>` / image digests.
    // Inside a credential-keyword anchor (`token = <hex>`, `api_key: <hex>`),
    // the keyword itself IS positive evidence - a 64-char hex assigned to
    // `apiKey` is overwhelmingly the credential, not a checksum. Lifting the
    // blanket drop here is the +60 TP / +0.03 F1 lever on the mirror benchmark.
    if !is_credential_context {
        let hex_len = value.len();
        if [32, 40, 64, 128].contains(&hex_len) && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return true;
        }
    }

    value.starts_with("data:image/")
}

fn passes_plausibility_checks(
    value: &str,
    mode: PlausibilityMode,
    placeholder_keywords: &[String],
    is_credential_context: bool,
) -> bool {
    if matches_universal_rejection(value)
        || is_known_non_secret(value, is_credential_context)
        || is_placeholder_ci(value.as_bytes(), placeholder_keywords)
        || has_low_alnum_ratio(value)
    {
        return false;
    }

    if matches!(mode, PlausibilityMode::Strict)
        && !passes_strict_secret_checks(value, is_credential_context)
    {
        return false;
    }
    true
}

fn matches_universal_rejection(value: &str) -> bool {
    value.contains("://")
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("${{")
        || value.starts_with("{{")
        || value.starts_with("${")
        || value.starts_with("(?")
        || value.starts_with('^')
        || value.starts_with("ssh-")
        || value.starts_with("ecdsa-")
        || (value.starts_with("eyJ") && value.matches('.').count() == 2)
        || value.starts_with("$ANSIBLE_VAULT")
        || value.starts_with("ENC[")
        || value.starts_with("-----BEGIN")
        || (value.starts_with("Ag") && value.len() > 40)
        || value.starts_with("age1")
        || value.starts_with("vault:")
        || value.starts_with("AQI")
        || value.starts_with("CiQ")
        || (value.len() > 2
            && value.as_bytes()[1] == b':'
            && value.as_bytes()[0].is_ascii_alphabetic()
            && (value.as_bytes()[2] == b'\\' || value.as_bytes()[2] == b'/'))
        || value.starts_with("```")
        || value.starts_with("---")
        || value.starts_with("===")
}

fn has_low_alnum_ratio(value: &str) -> bool {
    let alnum =
        value.chars().filter(|ch| ch.is_alphanumeric()).count() as f64 / value.len().max(1) as f64;
    alnum < 0.5
}

fn passes_strict_secret_checks(value: &str, is_credential_context: bool) -> bool {
    // Outside a credential-keyword anchor, any >10-char pure-hex value is a
    // checksum/digest, not a credential. Inside one (`apiKey: <hex>`), the
    // keyword is positive evidence the hex IS the credential - the entropy
    // path's strict mode would otherwise drop every md5/sha1/sha256-shaped
    // planted secret. Mirror v30 had 112 generic-high-entropy-string FNs
    // driven by exactly this gate firing in credential context.
    if !is_credential_context && value.chars().all(|ch| ch.is_ascii_hexdigit()) && value.len() > 10
    {
        return false;
    }
    if value.len() > 4 {
        if let Some(first) = value.chars().next() {
            if value.chars().all(|ch| ch == first) {
                return false;
            }
        }
    }
    if value.len() > 16 && unique_char_count(value) < 8 {
        return false;
    }
    if value.len() > 16 && second_half_entropy(value) < 2.5 {
        return false;
    }
    // Defect #81: entropy-api-key was firing on Java/Go camelCase and
    // PascalCase identifiers like `BulkUpdateApiKeyResponse`,
    // `convertSearchHitToVersionedApiKeyDoc`, `targetVersionedDocs`
    // (149 FPs in one ApiKeyService.java alone). These pass every
    // other check - high entropy, mixed case, decent length, no
    // placeholder words - but they're clearly source-code symbols,
    // not credentials. Reject strings that look like programming-
    // language identifiers: only letters/underscore, no digits, and
    // a camelCase / PascalCase shape (at least one internal
    // uppercase boundary). Real secrets virtually always include
    // digits or special characters.
    if looks_like_program_identifier(value) {
        return false;
    }

    shannon_entropy(value.as_bytes()) >= HIGH_ENTROPY_THRESHOLD
}

/// Heuristic: is this string a likely source-code identifier rather
/// than a credential? Identifiers in mainstream languages are all
/// `[A-Za-z_]` (no digits) with camelCase / PascalCase / snake_case
/// shape. Real API keys almost always include at least one digit (the
/// few that don't are short - `<8` chars - and rejected upstream by
/// length gates).
pub fn looks_like_program_identifier(value: &str) -> bool {
    // Letters + underscore only. Any digit, hyphen, slash, or special
    // char means it's not a typical identifier.
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphabetic() || ch == '_')
    {
        return false;
    }
    // snake_case (lowercase + underscore segments) - `my_long_helper_name`.
    if value.contains('_') && value.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_') {
        return true;
    }
    // camelCase / PascalCase - at least one internal lower→Upper
    // boundary. `BulkUpdateApiKeyResponse` has many; `Foo` has none.
    let bytes = value.as_bytes();
    let mut transitions = 0usize;
    for pair in bytes.windows(2) {
        if pair[0].is_ascii_lowercase() && pair[1].is_ascii_uppercase() {
            transitions += 1;
        }
    }
    transitions >= 1
}

fn unique_char_count(value: &str) -> usize {
    let mut seen = std::collections::HashSet::new();
    for ch in value.chars() {
        seen.insert(ch);
    }
    seen.len()
}

fn second_half_entropy(value: &str) -> f64 {
    let mid = value.len() / 2;
    let half_start = crate::floor_char_boundary(value, mid);
    shannon_entropy(&value.as_bytes()[half_start..])
}

pub fn is_candidate_plausible(value: &str, placeholder_keywords: &[String]) -> bool {
    passes_plausibility_checks(value, PlausibilityMode::Lenient, placeholder_keywords, false)
}

pub fn is_secret_plausible(value: &str, placeholder_keywords: &[String]) -> bool {
    passes_plausibility_checks(value, PlausibilityMode::Strict, placeholder_keywords, false)
}

/// Credential-context-aware plausibility check (Lenient mode).
///
/// Pass `is_credential_context = true` when the candidate came from a line
/// containing a credential keyword (`token`, `api_key`, `password`, ...).
/// In that case the hex-digest blacklist is skipped so md5/sha1/sha256-shaped
/// values can surface as candidates - the credential keyword anchor provides
/// the positive evidence that they're secrets, not digests.
pub fn is_candidate_plausible_with_context(
    value: &str,
    placeholder_keywords: &[String],
    is_credential_context: bool,
) -> bool {
    passes_plausibility_checks(
        value,
        PlausibilityMode::Lenient,
        placeholder_keywords,
        is_credential_context,
    )
}

/// Credential-context-aware plausibility check (Strict mode, for quoted values).
pub fn is_secret_plausible_with_context(
    value: &str,
    placeholder_keywords: &[String],
    is_credential_context: bool,
) -> bool {
    passes_plausibility_checks(
        value,
        PlausibilityMode::Strict,
        placeholder_keywords,
        is_credential_context,
    )
}

fn is_placeholder_ci(bytes: &[u8], placeholder_keywords: &[String]) -> bool {
    if placeholder_keywords.iter().any(|placeholder| {
        let placeholder_bytes = placeholder.as_bytes();
        bytes
            .windows(placeholder_bytes.len())
            .any(|window| window.eq_ignore_ascii_case(placeholder_bytes))
    }) {
        return true;
    }

    let upper = String::from_utf8_lossy(bytes).to_uppercase();
    upper.contains("EXAMPLE")
        || upper.contains("YOUR_")
        || upper.contains("REPLACE_ME")
        || upper.contains("CHANGE_ME")
        || upper.contains("INSERT_HERE")
        || upper.contains("FAKE_")
        || upper.contains("DUMMY_")
        || upper.contains("MOCK_")
        || (upper.contains("SECRET_KEY") && upper.len() < 20)
        || (upper.starts_with("AKIA")
            && (upper.ends_with("EXAMPLE") || upper.contains("1234567890")))
        || bytes.contains(&b'<')
        || bytes.contains(&b'>')
        || matches!(
            bytes,
            b"null" | b"none" | b"undefined" | b"empty" | b"default" | b"secret" | b"password"
        )
}
