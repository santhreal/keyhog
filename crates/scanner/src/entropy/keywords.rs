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

/// Heuristic for "this value looks like an English-prose run", not a
/// credential. Tightens FP filtering when the keyword-anchor is weak
/// (e.g. the word `secret` appears in a comment or commit message that
/// happens to also contain a high-entropy looking token-substring). Real
/// credentials never contain consecutive lowercase ASCII letters longer
/// than ~12 chars (longest common English word still in heavy use), and
/// they don't contain multiple whitespace-delimited words.
///
/// Returns true if `value` should be treated as English prose.
fn looks_like_english_prose(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 16 {
        return false;
    }

    // Branch 1: pure lowercase ASCII letters with no digit/symbol. A 16+
    // char string of nothing but lowercase letters is overwhelmingly a
    // dictionary-word concatenation, joined sentence fragment, or
    // identifier sentence (e.g. `description = "thequickbrownfoxjumps..."`
    // emitted from a free-text field). Real high-entropy credentials at
    // this length virtually always include at least one digit or a
    // mixed-case transition - the entropy of pure-lowercase-letters tops
    // out at log2(26) = 4.7 bits/byte, but English compressed via the
    // narrow vowel/consonant alternation lands well under that.
    if bytes.iter().all(|b| b.is_ascii_lowercase()) && bytes.len() >= 16 {
        return true;
    }

    // Branch 2: multi-word whitespace-bearing prose. The dotenv / log-line
    // / properties extractors occasionally capture the entire RHS as a
    // single value when the source is `KEY=this is the description of
    // something interesting and long`. The whitespace-bearing gate at the
    // emit site already drops these unconditionally for the entropy
    // fallback, but Strict-mode plausibility (called from quoted-value
    // extraction) sees the raw string and needs an explicit prose branch:
    // 2+ whitespace-separated tokens where every token is 2+ chars of
    // pure ASCII letters (any case) and there is at least one lowercase
    // run of 3+ chars. Real credentials never split into multiple
    // alphabetic tokens.
    let tokens: Vec<&str> = value.split_whitespace().collect();
    if tokens.len() >= 2 {
        let all_alpha = tokens
            .iter()
            .all(|t| t.len() >= 2 && t.bytes().all(|b| b.is_ascii_alphabetic()));
        if all_alpha {
            let has_lowercase_word =
                tokens.iter().any(|t| t.len() >= 3 && t.bytes().all(|b| b.is_ascii_lowercase()));
            if has_lowercase_word {
                return true;
            }
        }
    }

    false
}

/// Public predicate for callers in the entropy emit-path. Returns true
/// when the value would be classified as English prose; the emit-path
/// uses this to tighten plausibility when no strong credential keyword
/// anchor is adjacent.
pub fn entropy_value_looks_like_prose(value: &str) -> bool {
    looks_like_english_prose(value)
}

#[cfg(test)]
mod english_prose_tests {
    use super::{entropy_value_looks_like_prose, looks_like_english_prose};

    #[test]
    fn long_pure_lowercase_is_prose() {
        // Positive prose: 32-char pure lowercase is overwhelmingly a
        // joined sentence fragment / variable name run, not a credential.
        assert!(looks_like_english_prose(
            "thequickbrownfoxjumpsoverthelazydog"
        ));
    }

    #[test]
    fn mixed_case_credential_is_not_prose() {
        // Negative twin: a real-world high-entropy credential with mixed
        // case must NOT be flagged as prose.
        assert!(!looks_like_english_prose(
            "Hk9PqRsTuVwXyZAbCdEfGhIjKlMnOpQr"
        ));
    }

    #[test]
    fn alphanumeric_credential_is_not_prose() {
        // Negative twin: any digit in the value disqualifies it from the
        // prose classification.
        assert!(!looks_like_english_prose(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaa1234"
        ));
    }

    #[test]
    fn short_lowercase_is_not_prose() {
        // Negative twin: short values fall under the 16-char floor.
        assert!(!looks_like_english_prose("password"));
    }

    #[test]
    fn public_alias_is_consistent() {
        // Public re-export points at the same predicate.
        assert!(entropy_value_looks_like_prose(
            "thisismyverylongpassphraseinpurelowercase"
        ));
        assert!(!entropy_value_looks_like_prose("Abcd1234EfGhIjKlMnOpQrStUvWx"));
    }

    #[test]
    fn multi_word_alphabetic_is_prose() {
        // Positive: a multi-word English fragment captured as the
        // value of a `description=` style field gets dropped as prose.
        // The entropy emit-path already drops whitespace-bearing values
        // wholesale, but Strict-mode plausibility (quoted-string path)
        // sees the same shape and must also classify it as prose.
        assert!(looks_like_english_prose(
            "this is the description of something"
        ));
        assert!(looks_like_english_prose(
            "Session opened with handle XYZ"
        ));
    }

    #[test]
    fn multi_token_mixed_high_entropy_is_not_prose() {
        // Negative twin: a multi-token value where one token is
        // a high-entropy token (digits + mixed case) must NOT be
        // classified as prose - real credentials get pasted into
        // values that may carry surrounding whitespace from naive
        // shell joins, and we must not over-suppress them.
        assert!(!looks_like_english_prose(
            "key=Hk9PqRsTuV4kYBiZ0Q1A2B3C"
        ));
    }

    #[test]
    fn sixteen_char_pure_lowercase_is_prose() {
        // Positive recall: lowering the floor from 24 to 16 catches
        // shorter joined-word shapes that the prior gate walked past.
        // `description = "configurationhelper"` would surface as a
        // generic-secret/entropy candidate without this.
        assert!(looks_like_english_prose("configurationmgr"));
    }

    #[test]
    fn fifteen_char_pure_lowercase_is_not_prose() {
        // Negative twin: just below the floor stays admitted.
        assert!(!looks_like_english_prose("configurationm"));
    }
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

    // Symbolic-charset / credential-anchored entropy relaxation.
    // The blanket `HIGH_ENTROPY_THRESHOLD` (4.5) floor over-rejects
    // real symbolic-password shapes whose Shannon entropy lands in
    // the 3.5-4.5 band - e.g. `1E1B3b4Ho$U4kYBi` (entropy ~3.95),
    // `Y6NPMwS*rWGUv!JQnSG6a#D14` (entropy ~4.1). When the value
    // arrives WITH a strong credential-keyword anchor AND carries
    // at least one symbolic (non-alphanumeric) character, the
    // anchor + symbol-set together are positive evidence that the
    // value is a credential, not a code identifier or English word.
    // Use a lower 3.5 floor in that case. Pure-alphanumeric values
    // keep the original 4.5 floor (those are harder to distinguish
    // from CamelCase/snake_case identifiers).
    let entropy = shannon_entropy(value.as_bytes());
    if entropy >= HIGH_ENTROPY_THRESHOLD {
        return true;
    }
    if is_credential_context {
        let has_symbol = value.bytes().any(|b| !b.is_ascii_alphanumeric());
        if has_symbol && entropy >= 3.5 {
            return true;
        }
    }
    false
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

#[cfg(test)]
mod strict_secret_tests {
    use super::passes_strict_secret_checks;

    #[test]
    fn symbolic_password_in_credential_context_admitted() {
        // Positive recall: a real-world symbolic password whose Shannon
        // entropy lands in the 3.5-4.5 band (below the blanket high-
        // entropy floor) gets admitted when the value sits in a
        // credential-keyword anchored context. Catches the FN class
        // described in the generic-password investigator findings
        // (Y6NPMwS*rWGUv!JQnSG6a#D14, 1E1B3b4Ho$U4kYBi, etc.).
        assert!(passes_strict_secret_checks(
            "1E1B3b4Ho$U4kYBi",
            true,
        ));
        assert!(passes_strict_secret_checks(
            "Y6NPMwS*rWGUv!JQnSG6a#D14",
            true,
        ));
    }

    #[test]
    fn pure_alnum_low_entropy_in_credential_context_rejected() {
        // Negative twin: a pure-alphanumeric value with sub-4.5 entropy
        // and NO symbol stays rejected even in credential context - the
        // anchor + symbol-set combo is what lifts the floor; alphanumeric
        // alone is indistinguishable from CamelCase identifiers.
        assert!(!passes_strict_secret_checks(
            "abcdefghij1234567",
            true,
        ));
    }

    #[test]
    fn symbolic_value_no_anchor_keeps_high_floor() {
        // Negative twin: outside credential context, the relaxation
        // does not apply - a symbolic 3.5-4.5 entropy value alone is
        // not enough signal without the keyword anchor.
        // `H!l$o-w0rld-pas` has symbols and ~3.7 entropy, below the
        // 4.5 blanket floor, with no anchor - must stay rejected.
        assert!(!passes_strict_secret_checks(
            "H!l$o-w0rld-pas",
            false,
        ));
    }

    #[test]
    fn english_prose_with_anchor_still_rejected() {
        // Adversarial: a credential-anchored value that happens to be
        // English prose stays rejected - the prose-shape filter at
        // higher emit-path tiers catches this, but the strict checker
        // also gates on entropy floors which prose fails.
        // `passwordispasswordispassword` is pure-lowercase 28 chars,
        // entropy lands around 3.0 - both alnum-only branches reject.
        assert!(!passes_strict_secret_checks(
            "passwordispasswordispassword",
            true,
        ));
    }
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
