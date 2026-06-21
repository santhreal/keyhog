use super::plausibility::{is_candidate_plausible, is_secret_plausible, PlausibilityContext};
use crate::engine::phase2_generic::keywords::normalize_assignment_keyword;
use crate::engine::phase2_generic::shape_helpers::is_structured_dotted_token;

pub(crate) struct KeywordContext {
    pub(crate) keyword: String,
    pub(crate) threshold: f64,
    pub(crate) min_len: usize,
    pub(crate) is_credential_context: bool,
    /// CredData candidate-generation lift (recall lane). When `true`, a STRONG
    /// credential-anchored line is allowed to GENERATE a candidate whose value
    /// is a canonical hash/UUID/serial shape (`is_canonical_non_secret_shape`),
    /// so the downstream MoE — the precision authority when
    /// `entropy_ml_authoritative` is on — can arbitrate it instead of the shape
    /// being hard-dropped at the generation source before the model ever sees
    /// it. This is the root candidate-GENERATION gap for the CredData `UUID`
    /// and `hex64` (AES-256 key) miss classes: ~83% of CredData misses never
    /// generate a candidate, and these two shapes are dropped HERE.
    ///
    /// Set ONLY when the MoE is the runtime precision authority
    /// (`ml_enabled && entropy_ml_authoritative`) AND the line is in credential
    /// context (a strong keyword anchor is positive evidence). Left `false`
    /// everywhere else, so the non-ML path's behaviour — and the SecretBench
    /// mirror precision (where `TOKEN=<32-hex>` is planted in BOTH the positive
    /// and the sha256/git-sha/k8s-uid negative classes) — is byte-identical:
    /// no model, no lift. The keyword-FREE path keeps the strict gate
    /// unconditionally (no anchor ⇒ no evidence ⇒ no lift).
    pub(crate) allow_canonical_shapes: bool,
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
    let trimmed = line.trim();
    if is_import_like(trimmed) {
        return false;
    }
    if line_has_credential_assignment_surface(line) {
        return true;
    }

    let line_bytes = line.as_bytes();
    let has_keyword = secret_keywords.iter().any(|keyword| {
        let keyword_bytes = keyword.as_bytes();
        line_bytes
            .windows(keyword_bytes.len())
            .any(|window| window.eq_ignore_ascii_case(keyword_bytes))
    });
    has_keyword && (line.contains('=') || line.contains(':'))
}

pub(super) fn is_likely_innocuous_line(line: &str) -> bool {
    let trimmed = line.trim();
    let starts_with_uri = trimmed.starts_with("http://")
        || trimmed.starts_with("https://")
        || trimmed.starts_with("ftp://")
        || trimmed.starts_with("file://")
        || trimmed.starts_with("ssh://")
        || trimmed.starts_with("git://");
    if starts_with_uri && line_has_credential_assignment_surface(trimmed) {
        return false;
    }
    if trimmed.starts_with("import ")
        || trimmed.starts_with("from ")
        || trimmed.starts_with("require(")
        || trimmed.starts_with("use ")
        || trimmed.starts_with("package ")
        || trimmed.starts_with("include ")
        || trimmed.starts_with("#include ")
        || starts_with_uri
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
    // CredData recall lane: when set (the MoE is authoritative and a strong
    // credential keyword anchors the line), the extraction-time canonical-shape
    // gate (`is_known_non_secret`'s UUID + hex32/40/64/128 arms) is released so a
    // UUID-bodied or 64-hex (AES-256) value is EXTRACTED as a candidate for the
    // model to arbitrate, instead of being dropped before any candidate exists.
    // This is the third (and earliest) of the three generation gates the lift
    // must release for the `UUID`/`hex64` miss classes.
    allow_canonical_shapes: bool,
) -> Vec<String> {
    let mut candidates = Vec::new();
    if is_likely_concatenation_fragment(line) {
        return candidates;
    }

    let mut push_candidate = |raw: &str, strict: bool, allow_structured_dotted: bool| {
        let cleaned = clean_candidate_value(raw);
        if cleaned.len() < min_length {
            return;
        }
        let structured_dotted = allow_structured_dotted && is_structured_dotted_token(cleaned);
        let plausible = structured_dotted
            || if strict {
                is_secret_plausible(
                    cleaned,
                    placeholder_keywords,
                    PlausibilityContext::new(is_credential_context, allow_canonical_shapes),
                )
            } else {
                is_candidate_plausible(
                    cleaned,
                    placeholder_keywords,
                    PlausibilityContext::new(is_credential_context, allow_canonical_shapes),
                )
            };
        if plausible && !candidates.iter().any(|c| c == cleaned) {
            candidates.push(cleaned.to_string());
        }
    };

    if let Some(value) = authorization_header_value(line) {
        push_candidate(value, false, false);
    }
    if let Some(value) = xml_assignment_value(line) {
        push_candidate(value, false, true);
    }

    if let Some(sep_pos) = line.find('=').or_else(|| line.find(':')) {
        push_candidate(&line[sep_pos + 1..], false, true);
    }

    for quote in ['"', '\''] {
        let mut start = None;
        for (index, ch) in line.char_indices() {
            if ch == quote {
                match start {
                    None => start = Some(index + 1),
                    Some(begin) => {
                        let content = &line[begin..index];
                        push_candidate(content, true, false);
                        start = None;
                    }
                }
            }
        }
    }

    candidates
}

fn is_import_like(trimmed: &str) -> bool {
    trimmed.starts_with("import")
        || trimmed.starts_with("package")
        || trimmed.starts_with("use ")
        || trimmed.starts_with("from ")
        || trimmed.starts_with("require(")
}

pub(crate) fn line_has_credential_assignment_surface(line: &str) -> bool {
    authorization_header_value(line).is_some()
        || assignment_keyword_for_line(line)
            .as_deref()
            .is_some_and(normalized_assignment_keyword_is_credential)
}

pub(crate) fn assignment_keyword_for_line(line: &str) -> Option<String> {
    if let Some(tag) = xml_assignment_tag(line) {
        return normalize_assignment_keyword(tag);
    }
    let mut fallback = None;
    for (sep_pos, _) in line
        .char_indices()
        .rev()
        .filter(|(_, ch)| matches!(ch, '=' | ':'))
    {
        let lhs = &line[..sep_pos];
        let Some(key) = lhs
            .rsplit(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.')))
            .find(|part| !part.is_empty())
        else {
            continue;
        };
        let Some(normalized) = normalize_assignment_keyword(key) else {
            continue;
        };
        if normalized_assignment_keyword_is_credential(&normalized) {
            return Some(normalized);
        }
        if fallback.is_none() {
            fallback = Some(normalized);
        }
    }
    fallback
}

pub(crate) fn normalized_assignment_keyword_is_credential(normalized: &str) -> bool {
    let compact: String = normalized
        .bytes()
        .filter(|b| *b != b'_')
        .map(|b| b.to_ascii_lowercase() as char)
        .collect();
    let separated_secret_suffix = normalized.contains('_')
        && matches!(
            normalized.rsplit('_').next(),
            Some("key" | "secret" | "token" | "password" | "passwd" | "pwd")
        );
    if separated_secret_suffix {
        return true;
    }
    matches!(
        compact.as_str(),
        "password"
            | "passwd"
            | "pwd"
            | "passphrase"
            | "token"
            | "secret"
            | "credential"
            | "bearer"
            | "authorization"
            | "apikey"
            | "accesskey"
            | "authkey"
            | "privatekey"
            | "signingkey"
            | "encryptionkey"
            | "masterkey"
            | "secretkey"
            | "sessionkey"
            | "clientsecret"
            | "appsecret"
            | "salt"
            | "nonce"
            | "seed"
            | "hmacsalt"
            | "hmacseed"
            | "passwordsalt"
    ) || compact.ends_with("salt")
        || compact.ends_with("nonce")
        || compact.ends_with("seed")
}

fn clean_candidate_value(raw: &str) -> &str {
    let trimmed = raw
        .trim()
        .trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ';' || c == ',');
    let end = match trimmed.find(|c: char| c.is_whitespace() || c == '&' || c == '<') {
        Some(index) => index,
        None => trimmed.len(),
    };
    trimmed[..end].trim_matches(|c: char| c == '"' || c == '\'' || c == '`' || c == ';' || c == ',')
}

fn authorization_header_value(line: &str) -> Option<&str> {
    let (name, rhs) = line.trim().split_once(':')?;
    if !name.trim().eq_ignore_ascii_case("authorization") {
        return None;
    }
    let rhs = rhs.trim();
    let lower = rhs.to_ascii_lowercase();
    let token = if lower.starts_with("bearer ") {
        &rhs[7..]
    } else if lower.starts_with("basic ") {
        &rhs[6..]
    } else {
        return None;
    };
    token.split_whitespace().next()
}

fn xml_assignment_tag(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    let start = trimmed.find('<')?;
    let after_open = &trimmed[start + 1..];
    if after_open.starts_with('/') || after_open.starts_with('!') || after_open.starts_with('?') {
        return None;
    }
    let tag_end = after_open.find('>')?;
    let tag = after_open[..tag_end].split_whitespace().next()?;
    if tag.is_empty() || tag.starts_with('/') {
        return None;
    }
    let close = format!("</{tag}>");
    trimmed[start + 1 + tag_end + 1..]
        .contains(&close)
        .then_some(tag)
}

fn xml_assignment_value(line: &str) -> Option<&str> {
    let tag = xml_assignment_tag(line)?;
    let trimmed = line.trim();
    let open_start = trimmed.find('<')?;
    let open_end = trimmed[open_start..].find('>')? + open_start;
    let close = format!("</{tag}>");
    let close_start = trimmed[open_end + 1..].find(&close)? + open_end + 1;
    let normalized = normalize_assignment_keyword(tag)?;
    normalized_assignment_keyword_is_credential(&normalized)
        .then_some(trimmed[open_end + 1..close_start].trim())
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
                    .unwrap_or("") // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
                    .trim()
            } else {
                trimmed
                    .rfind('\'')
                    .map(|index| &trimmed[index + 1..])
                    .unwrap_or("") // LAW10: missing/non-string field => empty; value then fails downstream shape/length checks, recall-safe
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
